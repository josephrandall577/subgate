package main

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// 内置可疑UA特征（小写子串匹配）
var builtinBadUA = []string{"curl", "wget", "python", "go-http-client", "java", "libcurl", "axios", "node-fetch", "scrapy", "aiohttp"}

type ctxIPKey struct{}

type ipLimiter struct {
	l    *rate.Limiter
	seen time.Time
}

type Gateway struct {
	store  *Store
	logger *Logger
	cloud  *CloudIPs
	proxy  *httputil.ReverseProxy
	mu     sync.Mutex
	lims   map[string]*ipLimiter
}

func NewGateway(store *Store, logger *Logger, cloud *CloudIPs) *Gateway {
	g := &Gateway{store: store, logger: logger, cloud: cloud, lims: map[string]*ipLimiter{}}
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			r := g.store.Rules() // 每次读取当前规则：上游地址改动即时生效
			if r.upstream == nil {
				return
			}
			pr.SetURL(r.upstream)
			pr.Out.Host = r.upstream.Host
			ip, _ := pr.In.Context().Value(ctxIPKey{}).(string)
			pr.Out.Header.Set("X-Real-IP", ip)
			pr.Out.Header.Set("X-Forwarded-For", ip)
			if pr.Out.Header.Get("X-Forwarded-Proto") == "" {
				proto := "http"
				if pr.In.TLS != nil {
					proto = "https"
				}
				pr.Out.Header.Set("X-Forwarded-Proto", proto)
			}
		},
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        64,
			IdleConnTimeout:     90 * time.Second, // 上游换IP后旧连接最多再活90s，新连接自动重新走DNS解析
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	go g.janitor()
	return g
}

// 过滤链：真实IP → 白名单(直接放行) → IP黑名单 → 云厂商IP → UA三层 → 路径 → 限速 → 反代。
// 路径末段长得像 token 才算（≥16位字母数字-_），避免把普通路径段计入统计
var tokenSeg = regexp.MustCompile(`^[0-9A-Za-z_-]{16,}$`)

// Token 提取：优先查询参数 ?token=；否则取路径末段（/prefix/TOKEN 形态，不依赖前缀配置）
func extractToken(req *http.Request) string {
	if t := req.URL.Query().Get("token"); t != "" {
		return t
	}
	p := strings.Trim(req.URL.Path, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	if tokenSeg.MatchString(p) {
		return p
	}
	return ""
}

// 拦截策略全局统一为静默断连；仅限速按规范返回429。Token黑名单不在链上（仅统计排除）。
func (g *Gateway) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r := g.store.Rules()
	ip := clientIP(req, r)
	e := &LogEntry{
		TS: time.Now(), IP: ip.String(), Method: req.Method,
		Path: req.URL.RequestURI(), UA: req.UserAgent(),
		Token: extractToken(req),
	}
	ww := &respWriter{ResponseWriter: w}
	defer func() {
		e.Status = ww.status
		e.Bytes = ww.bytes
		g.logger.Write(e)
	}()

	if containsAddr(r.white, ip) { // 白名单最高优先级：架构上直达反代
		g.forward(ww, req, ip)
		return
	}
	if containsAddr(r.black, ip) {
		g.block(ww, e, "IP黑名单")
		return
	}
	if p := g.cloud.Match(ip); p != "" {
		g.block(ww, e, "云厂商IP:"+p)
		return
	}
	ua := strings.ToLower(e.UA)
	if !matchAny(r.uaAllow, ua) { // UA白名单命中则跳过UA各层拦截
		if ua == "" {
			g.block(ww, e, "空UA")
			return
		}
		if matchAny(builtinBadUA, ua) {
			g.block(ww, e, "内置UA规则")
			return
		}
		if matchAny(r.uaBan, ua) {
			g.block(ww, e, "UA黑名单")
			return
		}
	}
	if r.subPath != "" && !strings.HasPrefix(req.URL.Path, r.subPath) {
		g.block(ww, e, "非订阅路径")
		return
	}
	if !g.allow(ip.String(), r.ratePerMin, r.rateBurst) {
		e.Block = "限速"
		http.Error(ww, "too many requests", http.StatusTooManyRequests)
		return
	}
	g.forward(ww, req, ip)
}

func (g *Gateway) forward(w *respWriter, req *http.Request, ip netip.Addr) {
	if g.store.Rules().upstream == nil {
		http.Error(w, "upstream not configured", http.StatusBadGateway)
		return
	}
	req = req.WithContext(context.WithValue(req.Context(), ctxIPKey{}, ip.String()))
	g.proxy.ServeHTTP(w, req)
	if w.hijacked && w.status == 0 {
		w.status = 101 // WebSocket 升级
	}
}

func (g *Gateway) block(w *respWriter, e *LogEntry, reason string) {
	e.Block = reason
	drop(w)
}

// drop 静默断连：不返回任何字节，防扫描探测。
func drop(w http.ResponseWriter) {
	if h, ok := w.(http.Hijacker); ok {
		if c, _, err := h.Hijack(); err == nil {
			c.Close()
			return
		}
	}
	w.WriteHeader(http.StatusForbidden)
}

func clientIP(req *http.Request, r *Rules) netip.Addr {
	var addr netip.Addr
	if ap, err := netip.ParseAddrPort(req.RemoteAddr); err == nil {
		addr = ap.Addr().Unmap()
	}
	// 仅当直连来源属于受信代理（CDN/隧道，如本机 cloudflared）时才信任真实IP头
	if r.header == "" || !containsAddr(r.trusted, addr) {
		return addr
	}
	v := req.Header.Get(r.header)
	if v == "" {
		return addr
	}
	// 取最右值：多跳头（如 X-Forwarded-For）中最右是受信代理实际看到的一跳，最左可被客户端伪造；CF-Connecting-IP 单值不受影响
	parts := strings.Split(v, ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	if a, err := netip.ParseAddr(last); err == nil {
		return a.Unmap()
	}
	return addr
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func matchAny(keywords []string, lowerUA string) bool {
	for _, k := range keywords {
		if k != "" && strings.Contains(lowerUA, k) {
			return true
		}
	}
	return false
}

// allow 按IP令牌桶限流。注：限速参数改动对已存在的桶延迟生效（闲置回收后重建）。
func (g *Gateway) allow(ip string, perMin float64, burst int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	lm := g.lims[ip]
	if lm == nil {
		lm = &ipLimiter{l: rate.NewLimiter(rate.Limit(perMin/60), burst)}
		g.lims[ip] = lm
	}
	lm.seen = time.Now()
	return lm.l.Allow()
}

func (g *Gateway) janitor() {
	for range time.Tick(10 * time.Minute) {
		g.sweepLimiters()
	}
}

func (g *Gateway) sweepLimiters() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, v := range g.lims {
		if time.Since(v.seen) > 30*time.Minute {
			delete(g.lims, k)
		}
	}
}

// respWriter 统计状态码与响应字节，供访问日志使用。
type respWriter struct {
	http.ResponseWriter
	status   int
	bytes    int64
	hijacked bool
}

func (w *respWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *respWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *respWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	c, rw, err := h.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return c, rw, err
}

func (w *respWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

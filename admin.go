package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed admin.html
var adminHTML []byte

const sessionTTL = 24 * time.Hour

type Admin struct {
	store    *Store
	logger   *Logger
	cloud    *CloudIPs
	prefix   string
	mu       sync.Mutex
	sessions map[string]time.Time
	mux      *http.ServeMux
}

func NewAdmin(store *Store, logger *Logger, cloud *CloudIPs) *Admin {
	_, panel := store.SecretsInfo()
	a := &Admin{store: store, logger: logger, cloud: cloud, prefix: "/" + panel, sessions: map[string]time.Time{}}
	p := a.prefix
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+p, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, p+"/", http.StatusFound)
	})
	mux.HandleFunc("GET "+p+"/{$}", a.ui)
	mux.HandleFunc("GET "+p+"/api/meta", a.meta)
	mux.HandleFunc("POST "+p+"/api/login", a.login)
	reg := func(pat string, h http.HandlerFunc) { mux.Handle(pat, a.auth(h)) }
	reg("POST "+p+"/api/logout", a.logout)
	reg("GET "+p+"/api/logs", a.logsGet)
	reg("GET "+p+"/api/logs/export", a.logsExport)
	reg("POST "+p+"/api/logs/import", a.logsImport)
	reg("POST "+p+"/api/logs/cleanup", a.logsCleanup)
	reg("GET "+p+"/api/analysis", a.analysis)
	reg("GET "+p+"/api/lists", a.listsGet)
	reg("POST "+p+"/api/lists/add", a.listsAdd)
	reg("POST "+p+"/api/lists/del", a.listsDel)
	reg("POST "+p+"/api/lists/import", a.listsImport)
	reg("GET "+p+"/api/lists/export", a.listsExport)
	reg("GET "+p+"/api/settings", a.settingsGet)
	reg("POST "+p+"/api/settings", a.settingsPost)
	reg("POST "+p+"/api/password", a.passwordPost)
	reg("GET "+p+"/api/cloudips", a.cloudGet)
	reg("POST "+p+"/api/cloudips/refresh", a.cloudRefresh)
	reg("GET "+p+"/api/certinfo", a.certInfo)
	// 隐藏路径之外的一切访问：静默断连，不提示
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { drop(w) })
	a.mux = mux
	return a
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(v)
}

func (a *Admin) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sgs"); err == nil {
			a.mu.Lock()
			exp, ok := a.sessions[c.Value]
			if ok && time.Now().Before(exp) {
				a.sessions[c.Value] = time.Now().Add(sessionTTL)
				a.mu.Unlock()
				next(w, r)
				return
			}
			delete(a.sessions, c.Value)
			a.mu.Unlock()
		}
		jsonErr(w, http.StatusUnauthorized, "未登录或会话已过期")
	})
}

func (a *Admin) ui(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(adminHTML)
}

func (a *Admin) meta(w http.ResponseWriter, _ *http.Request) {
	jsonOK(w, map[string]string{"title": a.store.Config().PanelTitle})
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if readJSON(r, &in) != nil || !a.store.CheckLogin(in.User, in.Pass) {
		time.Sleep(600 * time.Millisecond) // 拖慢爆破
		jsonErr(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	tok := randHex(16)
	now := time.Now()
	a.mu.Lock()
	for k, exp := range a.sessions { // 顺手清过期会话
		if now.After(exp) {
			delete(a.sessions, k)
		}
	}
	a.sessions[tok] = now.Add(sessionTTL)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "sgs", Value: tok, Path: a.prefix + "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	jsonOK(w, map[string]bool{"ok": true})
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sgs"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sgs", Value: "", Path: a.prefix + "/", MaxAge: -1})
	jsonOK(w, map[string]bool{"ok": true})
}

func (a *Admin) logsGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 0
	fmt.Sscanf(q.Get("limit"), "%d", &limit)
	entries := a.logger.Query(QueryOpts{
		Range: q.Get("range"), IP: strings.TrimSpace(q.Get("ip")), Status: strings.TrimSpace(q.Get("status")),
		Token: strings.TrimSpace(q.Get("token")), UA: strings.TrimSpace(q.Get("ua")),
		SubOnly: q.Get("subonly") == "1", SubPrefix: a.store.Config().SubPath, Limit: limit,
	})
	jsonOK(w, map[string]any{"entries": entries})
}

func (a *Admin) logsExport(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="logs-%s-%s.jsonl"`, rng, time.Now().Format("20060102-150405")))
	for _, p := range a.logger.files(rng) {
		if f, err := os.Open(p); err == nil {
			io.Copy(w, f)
			f.Close()
		}
	}
}

func (a *Admin) logsImport(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 200<<20))
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "读取失败: "+err.Error())
		return
	}
	added, err := a.logger.Import(string(b))
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]int{"added": added})
}

func (a *Admin) logsCleanup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Days int `json:"days"`
	}
	if readJSON(r, &in) != nil {
		jsonErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	n, err := a.logger.Cleanup(in.Days)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]int{"removed": n})
}

func (a *Admin) analysis(w http.ResponseWriter, _ *http.Request) {
	cfg := a.store.Config()
	bl := map[string]bool{}
	for _, e := range cfg.TokenBlacklist {
		bl[e.Value] = true
	}
	jsonOK(w, a.logger.AnalyzeToday(bl, cfg.SuspTokenIPs, cfg.SuspIPTokens))
}

type listItem struct {
	Value  string `json:"value"`
	Remark string `json:"remark,omitempty"`
	Cloud  string `json:"cloud,omitempty"`
	Stats  []KV   `json:"stats,omitempty"`
}

func (a *Admin) listsGet(w http.ResponseWriter, _ *http.Request) {
	cfg := a.store.Config()
	plain := func(es []Entry) []listItem {
		out := make([]listItem, 0, len(es))
		for _, e := range es {
			out = append(out, listItem{Value: e.Value, Remark: e.Remark})
		}
		return out
	}
	black := make([]listItem, 0, len(cfg.IPBlacklist))
	for _, e := range cfg.IPBlacklist {
		it := listItem{Value: e.Value, Remark: e.Remark}
		if p, err := parsePrefixLoose(e.Value); err == nil {
			it.Cloud = a.cloud.Match(p.Addr()) // 辅助标注：是否属于云厂商网段
		}
		black = append(black, it)
	}
	tokens := make([]listItem, 0, len(cfg.TokenBlacklist))
	vals := make([]string, 0, len(cfg.TokenBlacklist))
	for _, e := range cfg.TokenBlacklist {
		vals = append(vals, e.Value)
	}
	stats := a.logger.TokenStats(vals)
	for _, e := range cfg.TokenBlacklist {
		tokens = append(tokens, listItem{Value: e.Value, Remark: e.Remark, Stats: stats[e.Value]})
	}
	jsonOK(w, map[string]any{
		"ip_whitelist": plain(cfg.IPWhitelist), "ip_blacklist": black,
		"ua_ban": plain(cfg.UABan), "ua_allow": plain(cfg.UAAllow),
		"token_blacklist": tokens,
	})
}

func validListValue(list, value string) error {
	if value == "" {
		return fmt.Errorf("值不能为空")
	}
	if list == "ip_whitelist" || list == "ip_blacklist" {
		if _, err := parsePrefixLoose(value); err != nil {
			return fmt.Errorf("无效 IP/CIDR: %v", err)
		}
	}
	return nil
}

func (a *Admin) listsAdd(w http.ResponseWriter, r *http.Request) {
	var in struct{ List, Value, Remark string }
	if readJSON(r, &in) != nil {
		jsonErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	in.Value = strings.TrimSpace(in.Value)
	if err := validListValue(in.List, in.Value); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := a.store.Update(func(c *Config) error {
		l := c.list(in.List)
		if l == nil {
			return fmt.Errorf("未知列表")
		}
		for i := range *l {
			if (*l)[i].Value == in.Value {
				(*l)[i].Remark = in.Remark
				return nil
			}
		}
		*l = append(*l, Entry{Value: in.Value, Remark: in.Remark})
		return nil
	})
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (a *Admin) listsDel(w http.ResponseWriter, r *http.Request) {
	var in struct{ List, Value string }
	if readJSON(r, &in) != nil {
		jsonErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	err := a.store.Update(func(c *Config) error {
		l := c.list(in.List)
		if l == nil {
			return fmt.Errorf("未知列表")
		}
		out := (*l)[:0]
		for _, e := range *l {
			if e.Value != in.Value {
				out = append(out, e)
			}
		}
		*l = out
		return nil
	})
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// listsImport 批量导入（IP名单）：每行一条，"值[,备注]" 或 "值 备注"。
func (a *Admin) listsImport(w http.ResponseWriter, r *http.Request) {
	var in struct{ List, Text string }
	if readJSON(r, &in) != nil {
		jsonErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	if in.List != "ip_whitelist" && in.List != "ip_blacklist" {
		jsonErr(w, http.StatusBadRequest, "该列表不支持批量导入")
		return
	}
	added, skipped := 0, 0
	err := a.store.Update(func(c *Config) error {
		l := c.list(in.List)
		have := map[string]bool{}
		for _, e := range *l {
			have[e.Value] = true
		}
		for _, line := range strings.Split(in.Text, "\n") {
			line = strings.TrimSpace(strings.ReplaceAll(line, ",", " "))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			value := fields[0]
			remark := strings.Join(fields[1:], " ")
			if _, err := parsePrefixLoose(value); err != nil || have[value] {
				skipped++
				continue
			}
			have[value] = true
			*l = append(*l, Entry{Value: value, Remark: remark})
			added++
		}
		return nil
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]int{"added": added, "skipped": skipped})
}

func (a *Admin) listsExport(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("list")
	cfg := a.store.Config()
	l := cfg.list(name)
	if l == nil {
		jsonErr(w, http.StatusBadRequest, "未知列表")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.txt"`, name))
	for _, e := range *l {
		if e.Remark != "" {
			fmt.Fprintf(w, "%s,%s\n", e.Value, e.Remark)
		} else {
			fmt.Fprintln(w, e.Value)
		}
	}
}

func (a *Admin) settingsGet(w http.ResponseWriter, _ *http.Request) {
	cfg := a.store.Config()
	user, panel := a.store.SecretsInfo()
	jsonOK(w, map[string]any{
		"upstream": cfg.Upstream, "sub_path": cfg.SubPath,
		"gateway_addr": cfg.GatewayAddr, "admin_addr": cfg.AdminAddr,
		"panel_title": cfg.PanelTitle, "real_ip_header": cfg.RealIPHeader,
		"trusted_proxies": cfg.TrustedProxies,
		"rate_per_min":    cfg.RatePerMin, "rate_burst": cfg.RateBurst,
		"susp_token_ips": cfg.SuspTokenIPs, "susp_ip_tokens": cfg.SuspIPTokens,
		"cert_domain": cfg.CertDomain, "asn_url_template": cfg.ASNURLTemplate,
		"user": user, "panel_path": panel,
	})
}

func (a *Admin) settingsPost(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Upstream       string   `json:"upstream"`
		SubPath        string   `json:"sub_path"`
		GatewayAddr    string   `json:"gateway_addr"`
		AdminAddr      string   `json:"admin_addr"`
		PanelTitle     string   `json:"panel_title"`
		RealIPHeader   string   `json:"real_ip_header"`
		TrustedProxies []string `json:"trusted_proxies"`
		RatePerMin     float64  `json:"rate_per_min"`
		RateBurst      int      `json:"rate_burst"`
		SuspTokenIPs   int      `json:"susp_token_ips"`
		SuspIPTokens   int      `json:"susp_ip_tokens"`
		CertDomain     string   `json:"cert_domain"`
		ASNURLTemplate string   `json:"asn_url_template"`
	}
	if readJSON(r, &in) != nil {
		jsonErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	in.Upstream = strings.TrimSpace(in.Upstream)
	if u, err := url.Parse(in.Upstream); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		jsonErr(w, http.StatusBadRequest, "上游地址须为 http(s)://host[:port] 形式")
		return
	}
	if !strings.HasPrefix(in.SubPath, "/") {
		jsonErr(w, http.StatusBadRequest, "订阅路径须以 / 开头")
		return
	}
	for _, t := range in.TrustedProxies {
		if _, err := parsePrefixLoose(t); err != nil {
			jsonErr(w, http.StatusBadRequest, "无效受信代理网段: "+t)
			return
		}
	}
	if in.RatePerMin <= 0 || in.RateBurst < 1 || in.SuspTokenIPs < 1 || in.SuspIPTokens < 1 {
		jsonErr(w, http.StatusBadRequest, "限速/阈值须为正数")
		return
	}
	if !strings.Contains(in.GatewayAddr, ":") || !strings.Contains(in.AdminAddr, ":") {
		jsonErr(w, http.StatusBadRequest, "监听地址须为 host:port 或 :port")
		return
	}
	old := a.store.Config()
	err := a.store.Update(func(c *Config) error {
		c.Upstream, c.SubPath = in.Upstream, in.SubPath
		c.GatewayAddr, c.AdminAddr = in.GatewayAddr, in.AdminAddr
		c.PanelTitle, c.RealIPHeader = in.PanelTitle, strings.TrimSpace(in.RealIPHeader)
		c.TrustedProxies = in.TrustedProxies
		c.RatePerMin, c.RateBurst = in.RatePerMin, in.RateBurst
		c.SuspTokenIPs, c.SuspIPTokens = in.SuspTokenIPs, in.SuspIPTokens
		c.CertDomain, c.ASNURLTemplate = strings.TrimSpace(in.CertDomain), in.ASNURLTemplate
		return nil
	})
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	restart := old.GatewayAddr != in.GatewayAddr || old.AdminAddr != in.AdminAddr
	jsonOK(w, map[string]bool{"ok": true, "restart_needed": restart})
}

func (a *Admin) passwordPost(w http.ResponseWriter, r *http.Request) {
	var in struct{ User, Pass string }
	if readJSON(r, &in) != nil || strings.TrimSpace(in.User) == "" {
		jsonErr(w, http.StatusBadRequest, "参数错误")
		return
	}
	if len(in.Pass) < 8 {
		jsonErr(w, http.StatusBadRequest, "密码至少8位")
		return
	}
	if err := a.store.SetCredentials(strings.TrimSpace(in.User), in.Pass); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.mu.Lock()
	a.sessions = map[string]time.Time{} // 改密后全部会话失效
	a.mu.Unlock()
	jsonOK(w, map[string]bool{"ok": true})
}

func (a *Admin) cloudGet(w http.ResponseWriter, _ *http.Request) {
	jsonOK(w, map[string]any{"providers": a.cloud.Status()})
}

func (a *Admin) cloudRefresh(w http.ResponseWriter, _ *http.Request) {
	a.cloud.Refresh(a.store.Config().ASNURLTemplate)
	jsonOK(w, map[string]any{"providers": a.cloud.Status()})
}

func (a *Admin) certInfo(w http.ResponseWriter, _ *http.Request) {
	domain := a.store.Config().CertDomain
	if domain == "" {
		jsonOK(w, map[string]string{"error": "未配置证书监控域名（设置页填写对外域名）"})
		return
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", domain+":443", &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12})
	if err != nil {
		jsonOK(w, map[string]string{"error": err.Error()})
		return
	}
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	jsonOK(w, map[string]any{
		"domain": domain, "issuer": cert.Issuer.CommonName,
		"not_after": cert.NotAfter, "days_left": int(time.Until(cert.NotAfter).Hours() / 24),
	})
}

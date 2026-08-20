package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newTestGW(t *testing.T, upstream string, mut func(*Config)) (*Gateway, *Store, *Logger) {
	t.Helper()
	dir := t.TempDir()
	store, err := LoadStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(c *Config) error {
		c.Upstream = upstream
		c.SubPath = "/sub"
		c.RealIPHeader = "CF-Connecting-IP"
		c.TrustedProxies = []string{"127.0.0.0/8", "::1/128"}
		c.RatePerMin = 6000
		c.RateBurst = 1000
		if mut != nil {
			mut(c)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	logger, err := NewLogger(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	cloud := NewCloudIPs(filepath.Join(dir, "cloud_ips.json"))
	cloud.data["testcloud"] = &providerData{Name: "测试云", CIDRs: []string{"55.0.0.0/8"}}
	cloud.rebuild()
	return NewGateway(store, logger, cloud), store, logger
}

func TestGatewayChain(t *testing.T) {
	var lastRealIP atomic.Value
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastRealIP.Store(r.Header.Get("X-Real-IP"))
		w.Write([]byte("UPSTREAM_OK"))
	}))
	defer up.Close()

	gw, store, logger := newTestGW(t, up.URL, func(c *Config) {
		c.IPWhitelist = []Entry{{Value: "10.0.0.1"}}
		c.IPBlacklist = []Entry{{Value: "10.0.0.0/8"}}
		c.UABan = []Entry{{Value: "EvilBot"}}
		c.UAAllow = []Entry{{Value: "GoodClient"}}
		c.TokenBlacklist = []Entry{{Value: "watchedtoken"}}
	})
	srv := httptest.NewServer(gw)
	defer srv.Close()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	do := func(path, ip, ua string) (*http.Response, error) {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req.Header.Set("CF-Connecting-IP", ip)
		req.Header.Set("User-Agent", ua) // 空串时 Go 不发送 UA 头
		return client.Do(req)
	}
	wantOK := func(name, path, ip, ua string) {
		t.Helper()
		resp, err := do(path, ip, ua)
		if err != nil {
			t.Fatalf("%s: 应放行却被断连: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status=%d", name, resp.StatusCode)
		}
	}
	wantDrop := func(name, path, ip, ua string) {
		t.Helper()
		resp, err := do(path, ip, ua)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("%s: 应断连却返回 %d", name, resp.StatusCode)
		}
	}

	wantOK("正常订阅", "/sub?token=abc", "1.2.3.4", "Clash/1.0")
	if got, _ := lastRealIP.Load().(string); got != "1.2.3.4" {
		t.Fatalf("上游收到 X-Real-IP=%q", got)
	}
	wantOK("白名单优先于黑名单/UA/路径", "/anything", "10.0.0.1", "curl/8.0")
	wantDrop("IP黑名单", "/sub?token=a", "10.0.0.2", "Clash/1.0")
	wantDrop("云厂商IP", "/sub?token=a", "55.1.2.3", "Clash/1.0")
	wantDrop("内置UA规则", "/sub?token=a", "2.2.2.2", "curl/8.0")
	wantDrop("自定义UA黑名单", "/sub?token=a", "2.2.2.3", "MyEVILBOT/2.0")
	wantDrop("空UA", "/sub?token=a", "2.2.2.4", "")
	wantOK("UA白名单覆盖内置规则", "/sub?token=a", "2.2.2.5", "GoodClient curl/8.0")
	wantDrop("非订阅路径", "/", "2.2.2.6", "Clash/1.0")
	wantOK("Token黑名单仅监控不拦截", "/sub?token=watchedtoken", "2.2.2.7", "Clash/1.0")

	// 限速：60/min 突发2 → 第3个立即请求 429
	if err := store.Update(func(c *Config) error { c.RatePerMin = 60; c.RateBurst = 2; return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		resp, err := do("/sub?token=a", "7.7.7.7", "Clash/1.0")
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("限速前第%d个请求应放行: %v", i, err)
		}
		resp.Body.Close()
	}
	resp, err := do("/sub?token=a", "7.7.7.7", "Clash/1.0")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("限速应返回429, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 访问日志落盘且带拦截原因
	time.Sleep(100 * time.Millisecond)
	entries := logger.Query(QueryOpts{Range: "today", Limit: 1000})
	if len(entries) == 0 {
		t.Fatal("无访问日志")
	}
	found := false
	for _, e := range entries {
		if e.Block == "IP黑名单" {
			found = true
		}
	}
	if !found {
		t.Fatal("日志缺少拦截原因")
	}

	// BlockOnly 服务端过滤：只返拦截记录
	blocked := logger.Query(QueryOpts{Range: "today", Limit: 1000, BlockOnly: true})
	if len(blocked) == 0 {
		t.Fatal("BlockOnly 查询应有结果")
	}
	for _, e := range blocked {
		if e.Block == "" {
			t.Fatal("BlockOnly 查询返回了放行记录")
		}
	}

	// Hourly 桶总和 = 总请求数，独立IP > 0
	an := logger.AnalyzeToday(nil, 2, 2)
	sum := 0
	for _, hb := range an.Hourly {
		sum += hb.Total
	}
	if sum != an.Total || an.Total != len(entries) {
		t.Fatalf("Hourly 桶总和=%d, Total=%d, 日志条数=%d，应相等", sum, an.Total, len(entries))
	}
	if an.UniqIPs == 0 {
		t.Fatal("UniqIPs 应 > 0")
	}
}

func TestParsePrefixLoose(t *testing.T) {
	p, err := parsePrefixLoose("1.2.3.4")
	if err != nil || p.String() != "1.2.3.4/32" {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := parsePrefixLoose("10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if _, err := parsePrefixLoose("abc"); err == nil {
		t.Fatal("非法输入应报错")
	}
}

func TestClientIP(t *testing.T) {
	r := &Rules{header: "X-Forwarded-For", trusted: compilePrefixes([]string{"127.0.0.0/8"})}
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8")
	if ip := clientIP(req, r); ip.String() != "8.8.8.8" {
		t.Fatalf("受信来源应取头部最右IP(最左可伪造), got %s", ip)
	}
	req.RemoteAddr = "1.1.1.1:1234" // 非受信来源：忽略头，防伪造
	if ip := clientIP(req, r); ip.String() != "1.1.1.1" {
		t.Fatalf("非受信来源应取连接IP, got %s", ip)
	}
}

func TestLogImportDedupe(t *testing.T) {
	l, err := NewLogger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	line := `{"ts":"2024-01-02T03:04:05+08:00","ip":"1.1.1.1","method":"GET","path":"/sub?token=x","status":200,"bytes":10,"ua":"Clash"}`
	a1, err := l.Import(line + "\n" + line)
	if err != nil || a1 != 1 {
		t.Fatalf("同批重复应去重, added=%d err=%v", a1, err)
	}
	a2, _ := l.Import(line)
	if a2 != 0 {
		t.Fatalf("再次导入应全部去重, added=%d", a2)
	}
}

func TestExtractToken(t *testing.T) {
	cases := []struct{ url, want string }{
		{"/api/v1/client/subscribe?token=abc", "abc"}, // 查询参数优先,不限长度
		{"/nowhereOwO/b67c0722c6530ed44043a106e19868d1", "b67c0722c6530ed44043a106e19868d1"},
		{"/nowhereOwO/0ccf3f16f5fdbcec2dcd0c8244c70dd6&flag=meta", "0ccf3f16f5fdbcec2dcd0c8244c70dd6"}, // 客户端误用&拼参数（无?）
		{"/b67c0722c6530ed44043a106e19868d1", "b67c0722c6530ed44043a106e19868d1"},                      // 无前缀
		{"/sub/550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"},          // UUID
		{"/api/v1/client/subscribe", ""},                                                               // 末段是普通路径词,太短不算
		{"/sub/short", ""},
		{"/", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.url, nil)
		if got := extractToken(req); got != c.want {
			t.Errorf("extractToken(%q)=%q want %q", c.url, got, c.want)
		}
	}
}

func TestConfigSnapshotRace(t *testing.T) {
	store, err := LoadStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Update(func(c *Config) error {
		c.IPBlacklist = append(c.IPBlacklist, Entry{Value: "1.2.3.4"})
		return nil
	})
	done := make(chan struct{})
	go func() { // 写者：就地改写列表元素(listsAdd 改备注的形态)
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = store.Update(func(c *Config) error { c.IPBlacklist[0].Remark = "x"; return nil })
		}
	}()
	for i := 0; i < 100; i++ { // 读者：遍历快照(analysis/listsGet 的形态)
		for _, e := range store.Config().IPBlacklist {
			_ = e.Remark
		}
	}
	<-done
}

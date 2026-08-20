package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/bcrypt"
)

// Entry 名单条目：IP/CIDR、UA关键词或 Token。
type Entry struct {
	Value  string `json:"value"`
	Remark string `json:"remark,omitempty"`
}

// Config 运行期可变配置（后台可改、立即热生效；监听地址类改动需重启）
type Config struct {
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
	IPWhitelist    []Entry  `json:"ip_whitelist"`
	IPBlacklist    []Entry  `json:"ip_blacklist"`
	UABan          []Entry  `json:"ua_ban"`
	UAAllow        []Entry  `json:"ua_allow"`
	TokenBlacklist []Entry  `json:"token_blacklist"` // 语义：仅从统计中排除+监控，不拦截请求
}

func (c *Config) list(name string) *[]Entry {
	switch name {
	case "ip_whitelist":
		return &c.IPWhitelist
	case "ip_blacklist":
		return &c.IPBlacklist
	case "ua_ban":
		return &c.UABan
	case "ua_allow":
		return &c.UAAllow
	case "token_blacklist":
		return &c.TokenBlacklist
	}
	return nil
}

// Secrets 部署期一次性机密（升级/重启不得覆盖）
type Secrets struct {
	User      string `json:"user"`
	PassHash  string `json:"pass_hash"`
	PanelPath string `json:"panel_path"`
}

// Rules 网关热路径使用的已编译规则快照（atomic 替换实现热加载）
type Rules struct {
	upstream        *url.URL
	subPath, header string
	trusted         []netip.Prefix
	white, black    []netip.Prefix
	uaAllow, uaBan  []string
	ratePerMin      float64
	rateBurst       int
}

type Store struct {
	dir   string
	mu    sync.Mutex
	cfg   Config
	sec   Secrets
	rules atomic.Pointer[Rules]
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func defaultConfig() Config {
	return Config{
		SubPath:        "/api/v1/client/subscribe",
		GatewayAddr:    ":18080",
		AdminAddr:      "127.0.0.1:18081",
		PanelTitle:     "SubGate",
		RealIPHeader:   "CF-Connecting-IP",
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RatePerMin:     20,
		RateBurst:      5,
		SuspTokenIPs:   3,
		SuspIPTokens:   3,
		ASNURLTemplate: defaultASNTemplate,
	}
}

func applyDefaults(c *Config) {
	d := defaultConfig()
	if c.SubPath == "" {
		c.SubPath = d.SubPath
	}
	if c.GatewayAddr == "" {
		c.GatewayAddr = d.GatewayAddr
	}
	if c.AdminAddr == "" {
		c.AdminAddr = d.AdminAddr
	}
	if c.PanelTitle == "" {
		c.PanelTitle = d.PanelTitle
	}
	if c.RatePerMin <= 0 {
		c.RatePerMin = d.RatePerMin
	}
	if c.RateBurst <= 0 {
		c.RateBurst = d.RateBurst
	}
	if c.SuspTokenIPs < 1 {
		c.SuspTokenIPs = d.SuspTokenIPs
	}
	if c.SuspIPTokens < 1 {
		c.SuspIPTokens = d.SuspIPTokens
	}
	if c.ASNURLTemplate == "" {
		c.ASNURLTemplate = d.ASNURLTemplate
	}
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// writeSecrets 写入部署期机密；pass/panel 为空则随机生成。
func writeSecrets(dir, user, pass, panel string) (Secrets, error) {
	if user == "" {
		user = "admin"
	}
	if pass == "" {
		pass = randHex(12)
		fmt.Printf("生成管理员密码: %s\n", pass)
	}
	if panel == "" {
		panel = randHex(8)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return Secrets{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Secrets{}, err
	}
	sec := Secrets{User: user, PassHash: string(h), PanelPath: panel}
	return sec, writeJSONFile(filepath.Join(dir, "secrets.json"), sec)
}

func LoadStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}

	cp := filepath.Join(dir, "config.json")
	if b, err := os.ReadFile(cp); err == nil {
		if err := json.Unmarshal(b, &s.cfg); err != nil {
			return nil, fmt.Errorf("config.json 解析失败: %w", err)
		}
	} else {
		s.cfg = defaultConfig()
	}
	applyDefaults(&s.cfg)
	if err := writeJSONFile(cp, s.cfg); err != nil {
		return nil, err
	}

	sp := filepath.Join(dir, "secrets.json")
	if b, err := os.ReadFile(sp); err == nil {
		if err := json.Unmarshal(b, &s.sec); err != nil {
			return nil, fmt.Errorf("secrets.json 解析失败: %w", err)
		}
	} else {
		pass := randHex(12)
		sec, err := writeSecrets(dir, "admin", pass, "")
		if err != nil {
			return nil, err
		}
		s.sec = sec
		log.Printf("首次启动，已生成管理员账号 admin / %s ，后台路径 /%s/ （请立即记录）", pass, sec.PanelPath)
	}
	s.compile()
	return s, nil
}

func parsePrefixLoose(v string) (netip.Prefix, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return netip.Prefix{}, fmt.Errorf("空值")
	}
	if !strings.Contains(v, "/") {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return netip.Prefix{}, err
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.ParsePrefix(v)
}

func compilePrefixes(vals []string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range vals {
		if p, err := parsePrefixLoose(v); err == nil {
			out = append(out, p)
		} else if strings.TrimSpace(v) != "" {
			log.Printf("忽略无效 IP/CIDR: %q", v)
		}
	}
	return out
}

func (s *Store) compile() {
	c := &s.cfg
	r := &Rules{subPath: c.SubPath, header: c.RealIPHeader, ratePerMin: c.RatePerMin, rateBurst: c.RateBurst}
	if u, err := url.Parse(strings.TrimSpace(c.Upstream)); err == nil && u.Scheme != "" && u.Host != "" {
		r.upstream = u
	}
	vals := func(es []Entry) []string {
		out := make([]string, 0, len(es))
		for _, e := range es {
			out = append(out, e.Value)
		}
		return out
	}
	low := func(es []Entry) []string {
		var out []string
		for _, e := range es {
			if v := strings.ToLower(strings.TrimSpace(e.Value)); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	r.trusted = compilePrefixes(c.TrustedProxies)
	r.white = compilePrefixes(vals(c.IPWhitelist))
	r.black = compilePrefixes(vals(c.IPBlacklist))
	r.uaAllow = low(c.UAAllow)
	r.uaBan = low(c.UABan)
	s.rules.Store(r)
}

func (s *Store) Rules() *Rules { return s.rules.Load() }

// Update 修改配置：成功后重编译规则（网关立即生效）并落盘。
func (s *Store) Update(fn func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.cfg); err != nil {
		return err
	}
	applyDefaults(&s.cfg)
	s.compile()
	return writeJSONFile(filepath.Join(s.dir, "config.json"), s.cfg)
}

// Config 返回配置快照；各列表深拷贝，读者可安全并发使用（mutator 会就地改写底层数组）
func (s *Store) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cfg
	c.TrustedProxies = slices.Clone(c.TrustedProxies)
	c.IPWhitelist = slices.Clone(c.IPWhitelist)
	c.IPBlacklist = slices.Clone(c.IPBlacklist)
	c.UABan = slices.Clone(c.UABan)
	c.UAAllow = slices.Clone(c.UAAllow)
	c.TokenBlacklist = slices.Clone(c.TokenBlacklist)
	return c
}

func (s *Store) SecretsInfo() (user, panelPath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sec.User, s.sec.PanelPath
}

func (s *Store) CheckLogin(user, pass string) bool {
	s.mu.Lock()
	u, h := s.sec.User, s.sec.PassHash
	s.mu.Unlock()
	userOK := subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1
	passOK := bcrypt.CompareHashAndPassword([]byte(h), []byte(pass)) == nil
	return userOK && passOK
}

func (s *Store) SetCredentials(user, pass string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sec.User = user
	s.sec.PassHash = string(h)
	return writeJSONFile(filepath.Join(s.dir, "secrets.json"), s.sec)
}

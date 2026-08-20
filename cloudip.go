package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultASNTemplate = "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%d/%s"

// 云厂商 → ASN。数据源为 ipverse/asn-ip（每厂商统一格式，一个抓取器搞定）。
var cloudProviders = []struct {
	Key, Name string
	ASNs      []int
}{
	{"aliyun", "阿里云", []int{37963, 45102}},
	{"tencent", "腾讯云", []int{45090, 132203}},
	{"huawei", "华为云", []int{136907, 55990}},
	{"bytedance", "字节/火山引擎", []int{396986, 137718}},
	{"google", "Google Cloud", []int{396982}},
	{"aws", "AWS", []int{16509, 14618}},
	{"azure", "Azure", []int{8075}},
	{"digitalocean", "DigitalOcean", []int{14061}},
	{"ucloud", "UCloud", []int{135377}},
	{"vultr", "Vultr", []int{20473}},
}

type providerData struct {
	Name     string    `json:"name"`
	Fetched  time.Time `json:"fetched,omitempty"`
	Err      string    `json:"err,omitempty"`
	CIDRs    []string  `json:"cidrs"`
	prefixes []netip.Prefix
}

type CloudIPs struct {
	mu   sync.RWMutex
	path string
	data map[string]*providerData
}

func NewCloudIPs(path string) *CloudIPs {
	c := &CloudIPs{path: path, data: map[string]*providerData{}}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &c.data)
	}
	c.rebuild()
	return c
}

func (c *CloudIPs) rebuild() {
	for _, d := range c.data {
		d.prefixes = d.prefixes[:0]
		for _, s := range d.CIDRs {
			if p, err := netip.ParsePrefix(s); err == nil {
				d.prefixes = append(d.prefixes, p)
			}
		}
	}
}

func (c *CloudIPs) Match(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, d := range c.data {
		for _, p := range d.prefixes {
			if p.Contains(a) {
				return d.Name
			}
		}
	}
	return ""
}

type CloudStatus struct {
	Key     string    `json:"key"`
	Name    string    `json:"name"`
	Count   int       `json:"count"`
	Fetched time.Time `json:"fetched"`
	Err     string    `json:"err,omitempty"`
}

func (c *CloudIPs) Status() []CloudStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]CloudStatus, 0, len(cloudProviders))
	for _, pv := range cloudProviders {
		st := CloudStatus{Key: pv.Key, Name: pv.Name}
		if d := c.data[pv.Key]; d != nil {
			st.Count, st.Fetched, st.Err = len(d.CIDRs), d.Fetched, d.Err
		}
		out = append(out, st)
	}
	return out
}

var cloudHTTP = &http.Client{Timeout: 30 * time.Second}

func fetchCIDRs(url string) ([]string, error) {
	resp, err := cloudHTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := netip.ParsePrefix(line); err == nil {
			out = append(out, line)
		}
	}
	return out, nil
}

// Refresh 并发按厂商刷新。任一厂商抓取失败则保留该厂商旧数据，绝不用半份数据覆盖。
func (c *CloudIPs) Refresh(tmpl string) {
	if tmpl == "" {
		tmpl = defaultASNTemplate
	}
	results := make([]*providerData, len(cloudProviders))
	var rmu sync.Mutex
	var wg sync.WaitGroup
	for i, pv := range cloudProviders {
		wg.Add(1)
		go func(i int, name string, asns []int) {
			defer wg.Done()
			put := func(d *providerData) {
				rmu.Lock()
				results[i] = d
				rmu.Unlock()
			}
			var cidrs []string
			for _, asn := range asns {
				v4, err := fetchCIDRs(fmt.Sprintf(tmpl, asn, "ipv4-aggregated.txt"))
				if err != nil { // v4 失败视为该厂商本轮失败
					put(&providerData{Name: name, Err: fmt.Sprintf("AS%d: %v", asn, err)})
					return
				}
				cidrs = append(cidrs, v4...)
				v6, err := fetchCIDRs(fmt.Sprintf(tmpl, asn, "ipv6-aggregated.txt"))
				if err != nil { // v6 失败同样算该厂商本轮失败，保留旧数据（数据源对所有 ASN 都提供 v6 文件）
					put(&providerData{Name: name, Err: fmt.Sprintf("AS%d v6: %v", asn, err)})
					return
				}
				cidrs = append(cidrs, v6...)
			}
			if len(cidrs) == 0 {
				put(&providerData{Name: name, Err: "空数据"})
				return
			}
			put(&providerData{Name: name, Fetched: time.Now(), CIDRs: cidrs})
		}(i, pv.Name, pv.ASNs)
	}
	wg.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	for i, pv := range cloudProviders {
		r := results[i]
		if r == nil {
			continue
		}
		if r.Err != "" {
			log.Printf("云IP库刷新失败(%s): %s，保留旧数据", pv.Name, r.Err)
			if old := c.data[pv.Key]; old != nil {
				old.Err, old.Name = r.Err, pv.Name
			} else {
				c.data[pv.Key] = r
			}
			continue
		}
		c.data[pv.Key] = r
	}
	c.rebuild()
	if b, err := json.MarshalIndent(c.data, "", " "); err == nil {
		tmp := c.path + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			os.Rename(tmp, c.path)
		}
	}
	log.Printf("云厂商IP库刷新完成")
}

// AutoRefresh 启动时若缺数据或超过7天则刷新，此后每12小时检查一次。
func (c *CloudIPs) AutoRefresh(s *Store) {
	check := func() {
		need := false
		c.mu.RLock()
		for _, pv := range cloudProviders {
			d := c.data[pv.Key]
			if d == nil || time.Since(d.Fetched) > 7*24*time.Hour {
				need = true
				break
			}
		}
		c.mu.RUnlock()
		if need {
			c.Refresh(s.Config().ASNURLTemplate)
		}
	}
	check()
	for range time.Tick(12 * time.Hour) {
		check()
	}
}

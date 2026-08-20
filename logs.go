package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type LogEntry struct {
	TS     time.Time `json:"ts"`
	IP     string    `json:"ip"`
	Method string    `json:"method"`
	Path   string    `json:"path"`   // 含查询串（含token）
	Status int       `json:"status"` // 0 = 静默断连
	Bytes  int64     `json:"bytes"`
	UA     string    `json:"ua"`
	Token  string    `json:"token,omitempty"`
	Block  string    `json:"block,omitempty"` // 拦截原因，空=放行
}

const dayFmt = "2006-01-02"

func logFile(dir, day string) string { return filepath.Join(dir, "access-"+day+".jsonl") }

// Logger 按天写 JSONL 访问日志（天然滚动，清理=删文件）。
type Logger struct {
	mu  sync.Mutex
	dir string
	day string
	f   *os.File
}

func NewLogger(dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Logger{dir: dir}, nil
}

func (l *Logger) Write(e *LogEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	day := e.TS.Format(dayFmt)
	if l.f == nil || day != l.day {
		if l.f != nil {
			l.f.Close()
		}
		f, err := os.OpenFile(logFile(l.dir, day), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		l.f, l.day = f, day
	}
	l.f.Write(append(b, '\n'))
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}

func (l *Logger) files(rng string) []string {
	if rng != "all" {
		p := logFile(l.dir, time.Now().Format(dayFmt))
		if _, err := os.Stat(p); err == nil {
			return []string{p}
		}
		return nil
	}
	m, _ := filepath.Glob(filepath.Join(l.dir, "access-*.jsonl"))
	sort.Strings(m)
	return m
}

func forEachEntry(files []string, fn func(LogEntry)) {
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var e LogEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				fn(e)
			}
		}
		f.Close()
	}
}

type QueryOpts struct {
	Range, IP, Status, Token, UA, SubPrefix string
	SubOnly                                 bool
	BlockOnly                               bool
	Limit                                   int
}

func (l *Logger) Query(o QueryOpts) []LogEntry {
	if o.Limit <= 0 || o.Limit > 5000 {
		o.Limit = 500
	}
	st := -1
	if o.Status != "" {
		if n, err := strconv.Atoi(o.Status); err == nil {
			st = n
		}
	}
	ua := strings.ToLower(o.UA)
	var out []LogEntry
	forEachEntry(l.files(o.Range), func(e LogEntry) {
		if o.IP != "" && !strings.Contains(e.IP, o.IP) {
			return
		}
		if st >= 0 && e.Status != st {
			return
		}
		if o.Token != "" && !strings.Contains(e.Token, o.Token) {
			return
		}
		if ua != "" && !strings.Contains(strings.ToLower(e.UA), ua) {
			return
		}
		if o.SubOnly && (o.SubPrefix == "" || !strings.HasPrefix(e.Path, o.SubPrefix)) {
			return
		}
		if o.BlockOnly && e.Block == "" {
			return
		}
		out = append(out, e)
	})
	if len(out) > o.Limit {
		out = out[len(out)-o.Limit:]
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i] // 最新在前
	}
	return out
}

// Import 合并外部 JSONL 日志：按天归档、按整行去重、按时间排序。
func (l *Logger) Import(text string) (int, error) {
	byDay := map[string][]LogEntry{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e LogEntry
		if json.Unmarshal([]byte(line), &e) != nil || e.TS.IsZero() {
			continue
		}
		byDay[e.TS.Format(dayFmt)] = append(byDay[e.TS.Format(dayFmt)], e)
	}
	if len(byDay) == 0 {
		return 0, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil { // 重写文件前放掉当前句柄，之后 Write 会重新打开
		l.f.Close()
		l.f, l.day = nil, ""
	}
	added := 0
	for day, list := range byDay {
		path := logFile(l.dir, day)
		seen := map[string]bool{}
		var all []LogEntry
		forEachEntry([]string{path}, func(e LogEntry) {
			b, _ := json.Marshal(e)
			if !seen[string(b)] {
				seen[string(b)] = true
				all = append(all, e)
			}
		})
		for _, e := range list {
			b, _ := json.Marshal(e)
			if !seen[string(b)] {
				seen[string(b)] = true
				all = append(all, e)
				added++
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].TS.Before(all[j].TS) })
		var sb strings.Builder
		for _, e := range all {
			b, _ := json.Marshal(e)
			sb.Write(b)
			sb.WriteByte('\n')
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
			return added, err
		}
		if err := os.Rename(tmp, path); err != nil {
			return added, err
		}
	}
	return added, nil
}

func (l *Logger) Cleanup(days int) (int, error) {
	if days < 1 {
		return 0, fmt.Errorf("天数须 >= 1")
	}
	cutoff := time.Now().AddDate(0, 0, -days).Format(dayFmt)
	files, _ := filepath.Glob(filepath.Join(l.dir, "access-*.jsonl"))
	n := 0
	for _, p := range files {
		d := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "access-"), ".jsonl")
		if d < cutoff { // ISO 日期字符串可直接比较
			if os.Remove(p) == nil {
				n++
			}
		}
	}
	return n, nil
}

type KV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type SuspToken struct {
	Token   string `json:"token"`
	IPCount int    `json:"ip_count"`
	Reqs    int    `json:"reqs"`
}

type SuspIP struct {
	IP         string `json:"ip"`
	TokenCount int    `json:"token_count"`
	Reqs       int    `json:"reqs"`
}

type HourBucket struct {
	Total   int `json:"total"`
	Blocked int `json:"blocked"`
}

type Analysis struct {
	Total      int            `json:"total"`
	Blocked    int            `json:"blocked"`
	UniqIPs    int            `json:"uniq_ips"`
	Hourly     [24]HourBucket `json:"hourly"`
	TopIPs     []KV           `json:"top_ips"`
	TopTokens  []KV           `json:"top_tokens"`
	SuspUA     []KV           `json:"susp_ua"`
	SuspTokens []SuspToken    `json:"susp_tokens"`
	SuspIPs    []SuspIP       `json:"susp_ips"`
}

func topKV(m map[string]int, n int) []KV {
	out := make([]KV, 0, len(m))
	for k, v := range m {
		out = append(out, KV{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// AnalyzeToday 扫描当日日志做分组计数。黑名单Token仅从Token维度统计排除（Total/Hourly/IP计数仍计入，监控语义）。
func (l *Logger) AnalyzeToday(tokenBL map[string]bool, tokenIPThresh, ipTokenThresh int) Analysis {
	a := Analysis{}
	ipc := map[string]int{}
	tkc := map[string]int{}
	bua := map[string]int{}
	tokIPs := map[string]map[string]int{}
	ipToks := map[string]map[string]bool{}
	forEachEntry(l.files("today"), func(e LogEntry) {
		a.Total++
		ipc[e.IP]++
		h := &a.Hourly[e.TS.Local().Hour()]
		h.Total++
		if e.Block != "" {
			a.Blocked++
			h.Blocked++
			bua[e.UA]++
		}
		if e.Token == "" || tokenBL[e.Token] {
			return
		}
		tkc[e.Token]++
		if tokIPs[e.Token] == nil {
			tokIPs[e.Token] = map[string]int{}
		}
		tokIPs[e.Token][e.IP]++
		if ipToks[e.IP] == nil {
			ipToks[e.IP] = map[string]bool{}
		}
		ipToks[e.IP][e.Token] = true
	})
	a.UniqIPs = len(ipc)
	a.TopIPs = topKV(ipc, 20)
	a.TopTokens = topKV(tkc, 20)
	a.SuspUA = topKV(bua, 20)
	for t, ips := range tokIPs {
		if len(ips) >= tokenIPThresh {
			a.SuspTokens = append(a.SuspTokens, SuspToken{Token: t, IPCount: len(ips), Reqs: tkc[t]})
		}
	}
	sort.Slice(a.SuspTokens, func(i, j int) bool { return a.SuspTokens[i].IPCount > a.SuspTokens[j].IPCount })
	for ip, ts := range ipToks {
		if len(ts) >= ipTokenThresh {
			a.SuspIPs = append(a.SuspIPs, SuspIP{IP: ip, TokenCount: len(ts), Reqs: ipc[ip]})
		}
	}
	sort.Slice(a.SuspIPs, func(i, j int) bool { return a.SuspIPs[i].TokenCount > a.SuspIPs[j].TokenCount })
	if len(a.SuspTokens) > 50 {
		a.SuspTokens = a.SuspTokens[:50]
	}
	if len(a.SuspIPs) > 50 {
		a.SuspIPs = a.SuspIPs[:50]
	}
	return a
}

// TokenStats 黑名单Token监控：今天各Token被哪些IP拉取过几次。
func (l *Logger) TokenStats(tokens []string) map[string][]KV {
	want := map[string]bool{}
	for _, t := range tokens {
		want[t] = true
	}
	acc := map[string]map[string]int{}
	forEachEntry(l.files("today"), func(e LogEntry) {
		if e.Token == "" || !want[e.Token] {
			return
		}
		if acc[e.Token] == nil {
			acc[e.Token] = map[string]int{}
		}
		acc[e.Token][e.IP]++
	})
	res := map[string][]KV{}
	for t, m := range acc {
		res[t] = topKV(m, 20)
	}
	return res
}

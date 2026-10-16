package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Threat intelligence lists: public lists of addresses known for command
// and control, malware hosting or anonymization (abuse.ch Feodo Tracker and
// ThreatFox, Spamhaus DROP, Tor exits). Only the server downloads
// them (agents never talk to third parties), and only when threat_intel is
// enabled. Nothing about this installation is sent; the requests are plain
// downloads.

type intelList struct {
	Name     string
	URL      string
	Severity string // of a connection to a listed address
	parse    func([]byte) []netip.Prefix
}

func parseIPLines(b []byte) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		line = strings.Fields(strings.SplitN(line, ";", 2)[0])[0]
		if p, err := netip.ParsePrefix(line); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(line); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

var threatFoxIP = regexp.MustCompile(`^"[^"]*",\s*"[^"]*",\s*"([0-9a-fA-F.:\[\]]+):[0-9]+"`)

// parseThreatFox reads the ip:port CSV export (the last 48 hours of IOCs).
func parseThreatFox(b []byte) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if m := threatFoxIP.FindStringSubmatch(sc.Text()); m != nil {
			if a, err := netip.ParseAddr(strings.Trim(m[1], "[]")); err == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	return out
}

func parseSpamhausJSON(b []byte) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		var row struct {
			CIDR string `json:"cidr"`
		}
		if json.Unmarshal(sc.Bytes(), &row) == nil && row.CIDR != "" {
			if p, err := netip.ParsePrefix(row.CIDR); err == nil {
				out = append(out, p.Masked())
			}
		}
	}
	return out
}

var intelLists = []intelList{
	{"feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "critical", parseIPLines},
	{"threatfox", "https://threatfox.abuse.ch/export/csv/ip-port/recent/", "critical", parseThreatFox},
	{"spamhaus-drop", "https://www.spamhaus.org/drop/drop_v4.json", "high", parseSpamhausJSON},
	{"tor-exit", "https://check.torproject.org/torbulkexitlist", "medium", parseIPLines},
}

type intelSet struct {
	mu      sync.RWMutex
	entries map[string][]netip.Prefix // list name -> sorted prefixes
	updated map[string]time.Time
	errs    map[string]string
}

// lookup returns the first list an address is on.
func (s *intelSet) lookup(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, l := range intelLists {
		ps := s.entries[l.Name]
		// prefixes are sorted by address; check the candidates around a
		i := sort.Search(len(ps), func(i int) bool { return ps[i].Addr().Compare(a) > 0 })
		for j := i - 1; j >= 0 && j >= i-64; j-- {
			if ps[j].Contains(a) {
				return l.Name, true
			}
		}
	}
	return "", false
}

func (s *intelSet) set(name string, ps []netip.Prefix, at time.Time) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].Addr().Compare(ps[j].Addr()) < 0 })
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries, s.updated, s.errs = map[string][]netip.Prefix{}, map[string]time.Time{}, map[string]string{}
	}
	s.entries[name], s.updated[name] = ps, at
	delete(s.errs, name)
}

func (s *intelSet) fail(name, err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errs == nil {
		s.entries, s.updated, s.errs = map[string][]netip.Prefix{}, map[string]time.Time{}, map[string]string{}
	}
	s.errs[name] = err
}

type intelStatus struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Entries int       `json:"entries"`
	Updated time.Time `json:"updated"`
	Error   string    `json:"error,omitempty"`
}

func (s *intelSet) status() []intelStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []intelStatus
	for _, l := range intelLists {
		out = append(out, intelStatus{Name: l.Name, URL: l.URL, Entries: len(s.entries[l.Name]), Updated: s.updated[l.Name], Error: s.errs[l.Name]})
	}
	return out
}

// refreshIntel loads cached lists from disk and downloads those older than
// twelve hours. Called at start and every hour.
func (s *Server) refreshIntel() {
	if !s.cfg.ThreatIntel {
		return
	}
	dir := filepath.Join(s.cfg.DataDir, "intel")
	os.MkdirAll(dir, 0o700)
	client := &http.Client{Timeout: 30 * time.Second}
	for _, l := range intelLists {
		path := filepath.Join(dir, l.Name+".txt")
		fi, err := os.Stat(path)
		s.intel.mu.RLock()
		loaded := !s.intel.updated[l.Name].IsZero()
		s.intel.mu.RUnlock()
		if err == nil && time.Since(fi.ModTime()) < 12*time.Hour {
			if !loaded {
				if b, err := os.ReadFile(path); err == nil {
					s.intel.set(l.Name, l.parse(b), fi.ModTime())
				}
			}
			continue
		}
		b, err := download(client, l.URL)
		if err == nil {
			if ps := l.parse(b); len(ps) == 0 {
				err = fmt.Errorf("no entries")
			} else {
				os.WriteFile(path, b, 0o600)
				s.intel.set(l.Name, ps, time.Now().UTC())
				continue
			}
		}
		log.Printf("threat intel %s: %v", l.Name, err)
		s.intel.fail(l.Name, err.Error())
		// keep using an older copy
		if !loaded {
			if b, rerr := os.ReadFile(path); rerr == nil && fi != nil {
				s.intel.set(l.Name, l.parse(b), fi.ModTime())
				s.intel.fail(l.Name, err.Error())
			}
		}
	}
}

func download(c *http.Client, url string) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "vigil/"+Version+" (+https://github.com/akquisio-dev/vigil)")
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, 16<<20))
}

// serviceProcesses never open outbound connections to the internet in normal
// operation; when they do, something is tunneling or exfiltrating.
var serviceProcesses = map[string]bool{"sshd": true, "postgres": true, "mysqld": true, "mariadbd": true, "redis-server": true, "mongod": true, "memcached": true}

var minerPorts = map[int]bool{3333: true, 14433: true, 14444: true, 45560: true, 45700: true}

func netPublic(ip string) bool {
	a := net.ParseIP(ip)
	return a != nil && !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}

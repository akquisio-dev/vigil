package server

import (
	"encoding/json"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Host load from the agents' metrics samples (one a minute). They are kept
// apart from the event store and state.json: a minute ring for a day, an
// hourly roll-up for a month, and the newest sample in full, all in
// metrics.json, written every few minutes. Losing them loses graphs, never
// evidence.

const (
	metricsMinutes = 24 * 60
	metricsHours   = 30 * 24
	metricsSaveGap = 5 * time.Minute
	metricsMaxAge  = 2 * time.Hour   // a sample older than this on arrival is dropped
	metricsStale   = 3 * time.Minute // a host's newest sample older than this is not drawn as now
)

// metricPoint is one minute, or one hour with the peaks of its minutes.
type metricPoint struct {
	T      int64   `json:"t"` // unix seconds
	CPU    float64 `json:"cpu"`
	IOWait float64 `json:"iow"`
	Steal  float64 `json:"st"`
	Mem    float64 `json:"mem"` // percent
	Swap   float64 `json:"swap"`
	Load   float64 `json:"l1"`
	RX     float64 `json:"rx"`
	TX     float64 `json:"tx"`
	DR     float64 `json:"dr"`
	DW     float64 `json:"dw"`
	Disk   float64 `json:"disk"`
	CI     int     `json:"ci"`
	CO     int     `json:"co"`
	CPUMax float64 `json:"cpu_max,omitempty"`
	MemMax float64 `json:"mem_max,omitempty"`
}

type hostMetrics struct {
	Minutes []metricPoint  `json:"minutes"`
	Hours   []metricPoint  `json:"hours"`
	Latest  *proto.Metrics `json:"latest,omitempty"` // newest sample that carried detail
	Last    *proto.Metrics `json:"last,omitempty"`   // newest sample of all
}

type metricsSet struct {
	mu    sync.Mutex
	hosts map[string]*hostMetrics
	dirty bool
	saved time.Time
}

func metricsFile(dir string) string { return filepath.Join(dir, "metrics.json") }

func (s *Server) loadMetrics() {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	s.metrics.hosts = map[string]*hostMetrics{}
	raw, err := os.ReadFile(metricsFile(s.cfg.DataDir))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("metrics: %v", err)
		}
		return
	}
	if err := json.Unmarshal(raw, &s.metrics.hosts); err != nil {
		log.Printf("metrics: %v (starting empty)", err)
		s.metrics.hosts = map[string]*hostMetrics{}
	}
	s.metrics.saved = time.Now()
}

// saveMetrics writes metrics.json when something changed, at most every
// metricsSaveGap unless forced. Agents deleted meanwhile are left out.
func (s *Server) saveMetrics(force bool) {
	s.mu.Lock()
	known := make(map[string]bool, len(s.state.Agents))
	for id := range s.state.Agents {
		known[id] = true
	}
	s.mu.Unlock()
	m := &s.metrics
	m.mu.Lock()
	if !m.dirty || (!force && time.Since(m.saved) < metricsSaveGap) {
		m.mu.Unlock()
		return
	}
	for id := range m.hosts {
		if !known[id] {
			delete(m.hosts, id)
		}
	}
	raw, err := json.Marshal(m.hosts)
	m.dirty, m.saved = false, time.Now()
	m.mu.Unlock()
	if err == nil {
		err = writeFileAtomic(metricsFile(s.cfg.DataDir), raw)
	}
	if err != nil {
		log.Printf("metrics: %v", err)
	}
}

func writeFileAtomic(path string, raw []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metrics-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func finite(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return v
}

func pct(v float64) float64 { return math.Min(100, finite(v)) }

func share(used, total uint64) float64 {
	if total == 0 || used > total {
		return 0
	}
	return math.Round(float64(used)/float64(total)*1000) / 10
}

// cleanMetrics bounds what an agent sends: every number finite, lists and
// names short.
func cleanMetrics(m proto.Metrics) proto.Metrics {
	m.CPU, m.IOWait, m.Steal, m.DiskPct = pct(m.CPU), pct(m.IOWait), pct(m.Steal), pct(m.DiskPct)
	for i := range m.Load {
		m.Load[i] = finite(m.Load[i])
	}
	m.RX, m.TX, m.DiskRead, m.DiskWrite = finite(m.RX), finite(m.TX), finite(m.DiskRead), finite(m.DiskWrite)
	if m.Cores < 0 || m.Cores > 4096 {
		m.Cores = 0
	}
	if len(m.Disks) > 8 {
		m.Disks = m.Disks[:8]
	}
	for i := range m.Disks {
		m.Disks[i].Mount, m.Disks[i].FS = clip(m.Disks[i].Mount, 200), clip(m.Disks[i].FS, 20)
	}
	if len(m.Ifaces) > 16 {
		m.Ifaces = m.Ifaces[:16]
	}
	for i := range m.Ifaces {
		f := &m.Ifaces[i]
		f.Name, f.RX, f.TX = clip(f.Name, 32), finite(f.RX), finite(f.TX)
		var addrs []string
		for _, a := range f.Addrs {
			if ip, err := netip.ParseAddr(a); err == nil && len(addrs) < 8 {
				addrs = append(addrs, ip.Unmap().String())
			}
		}
		f.Addrs = addrs
	}
	if len(m.Top) > 10 {
		m.Top = m.Top[:10]
	}
	for i := range m.Top {
		p := &m.Top[i]
		p.Comm, p.Exe, p.CPU = clip(p.Comm, 64), clip(p.Exe, 300), finite(p.CPU)
	}
	if len(m.Peers) > 64 {
		m.Peers = m.Peers[:64]
	}
	peers := m.Peers[:0]
	for _, p := range m.Peers {
		ip, err := netip.ParseAddr(p.IP)
		if err != nil || p.Port <= 0 || p.Port > 65535 || p.N <= 0 {
			continue
		}
		p.IP, p.Process = ip.Unmap().String(), clip(p.Process, 64)
		peers = append(peers, p)
	}
	m.Peers = peers
	return m
}

// pointOf keeps a tenth of a percent and whole bytes, which is all a graph
// shows and keeps metrics.json small.
func pointOf(m proto.Metrics) metricPoint {
	r1 := func(v float64) float64 { return math.Round(v*10) / 10 }
	return metricPoint{T: m.TS.Unix(), CPU: r1(m.CPU), IOWait: r1(m.IOWait), Steal: r1(m.Steal),
		Mem: share(m.MemUsed, m.MemTotal), Swap: share(m.SwapUsed, m.SwapTotal), Load: math.Round(m.Load[0]*100) / 100,
		RX: math.Round(m.RX), TX: math.Round(m.TX), DR: math.Round(m.DiskRead), DW: math.Round(m.DiskWrite), Disk: r1(m.DiskPct), CI: m.ConnIn, CO: m.ConnOut}
}

// rollup averages the minutes of one hour and keeps their peaks.
func rollup(ms []metricPoint, hour int64) metricPoint {
	h := metricPoint{T: hour}
	n := float64(len(ms))
	for _, m := range ms {
		h.CPU += m.CPU / n
		h.IOWait += m.IOWait / n
		h.Steal += m.Steal / n
		h.Mem += m.Mem / n
		h.Swap += m.Swap / n
		h.Load += m.Load / n
		h.RX += m.RX / n
		h.TX += m.TX / n
		h.DR += m.DR / n
		h.DW += m.DW / n
		h.Disk = math.Max(h.Disk, m.Disk)
		h.CI = max(h.CI, m.CI)
		h.CO = max(h.CO, m.CO)
		h.CPUMax = math.Max(h.CPUMax, m.CPU)
		h.MemMax = math.Max(h.MemMax, m.Mem)
	}
	r := func(v float64) float64 { return math.Round(v*10) / 10 }
	h.CPU, h.IOWait, h.Steal, h.Mem, h.Swap, h.Load = r(h.CPU), r(h.IOWait), r(h.Steal), r(h.Mem), r(h.Swap), math.Round(h.Load*100)/100
	h.RX, h.TX, h.DR, h.DW = math.Round(h.RX), math.Round(h.TX), math.Round(h.DR), math.Round(h.DW)
	return h
}

func (hm *hostMetrics) add(m proto.Metrics) {
	p := pointOf(m)
	if n := len(hm.Minutes); n > 0 {
		last := hm.Minutes[n-1]
		if p.T <= last.T {
			return // older or repeated sample
		}
		if hour := last.T / 3600 * 3600; p.T/3600*3600 != hour {
			var in []metricPoint
			for i := n - 1; i >= 0 && hm.Minutes[i].T >= hour; i-- {
				in = append(in, hm.Minutes[i])
			}
			if len(hm.Hours) == 0 || hm.Hours[len(hm.Hours)-1].T < hour {
				hm.Hours = append(hm.Hours, rollup(in, hour))
			}
			if over := len(hm.Hours) - metricsHours; over > 0 {
				hm.Hours = append([]metricPoint{}, hm.Hours[over:]...)
			}
		}
	}
	hm.Minutes = append(hm.Minutes, p)
	cut := p.T - int64(metricsMinutes)*60
	i := 0
	for i < len(hm.Minutes) && hm.Minutes[i].T <= cut {
		i++
	}
	if i > 0 {
		hm.Minutes = append([]metricPoint{}, hm.Minutes[i:]...)
	}
	cp := m
	hm.Last = &cp
	if m.Ifaces != nil || m.Top != nil || m.Peers != nil || m.Disks != nil {
		hm.Latest = &cp
	}
}

// metricsReceived stores the samples of one batch. It takes metrics.mu
// only, never s.mu.
func (s *Server) metricsReceived(agent string, list []proto.Metrics) {
	if len(list) == 0 {
		return
	}
	if len(list) > 60 {
		list = list[len(list)-60:]
	}
	now := time.Now()
	m := &s.metrics
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hosts == nil {
		m.hosts = map[string]*hostMetrics{}
	}
	hm := m.hosts[agent]
	if hm == nil {
		hm = &hostMetrics{}
		m.hosts[agent] = hm
	}
	for _, x := range list {
		if x.TS.After(now.Add(5*time.Minute)) || x.TS.Before(now.Add(-metricsMaxAge)) {
			continue
		}
		hm.add(cleanMetrics(x))
		m.dirty = true
	}
}

// metricsAddrs are the interface addresses each agent reported last.
// Caller holds metrics.mu.
func (m *metricsSet) addrsLocked() map[string][]string {
	out := map[string][]string{}
	for id, hm := range m.hosts {
		l := hm.Latest
		if l == nil {
			continue
		}
		for _, f := range l.Ifaces {
			out[id] = append(out[id], f.Addrs...)
		}
	}
	return out
}

func (s *Server) metricsAddrs() map[string][]string {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	return s.metrics.addrsLocked()
}

// ---------- dashboard ----------

type hostFlow struct {
	From       string `json:"from"` // the agent that opened the connections
	To         string `json:"to"`
	Port       int    `json:"port"`
	N          int    `json:"n"`
	ClientProc string `json:"client_proc,omitempty"`
	ServerProc string `json:"server_proc,omitempty"`
}

type hostCard struct {
	agentView
	Metrics *proto.Metrics `json:"metrics"`
	Spark   []metricPoint  `json:"spark"` // the last hour
	Server  bool           `json:"server"`
	ExtIn   int            `json:"ext_in"` // connections with public addresses that are none of our hosts
	ExtOut  int            `json:"ext_out"`
	Stale   bool           `json:"stale"` // the newest sample is older than metricsStale
}

// ownAddrs are the server's addresses: the agent sharing one of them runs
// on the same machine as the server. The packaged unit allows no netlink
// socket, so the interfaces cannot be listed there; the address the agent
// API listens on (a VPN address) names the machine as well.
func ownAddrs(listen ...string) map[string]bool {
	out := map[string]bool{}
	for _, l := range listen {
		if host, _, err := net.SplitHostPort(l); err == nil {
			if a, err := netip.ParseAddr(host); err == nil && !a.IsLoopback() && !a.IsUnspecified() {
				out[a.Unmap().String()] = true
			}
		}
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out[ipn.IP.String()] = true
		}
	}
	return out
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// hostGraph links the agents through the connections they report: an
// address belongs to an agent when it is one of its interface addresses
// or the address it reports from; an address claimed by two agents (the
// same private network behind two NATs) belongs to none. What is left
// with a public address counts as the internet; private addresses of no
// agent (containers, docker-proxy) and a host's own addresses count as
// neither. A host whose newest sample is older than metricsStale adds no
// links, its connections may be long gone.
func hostGraph(agents map[string]*AgentRec, metrics map[string]*hostMetrics, own map[string]bool, now time.Time) (flows []hostFlow, ext map[string][2]int, serverHost string) {
	owner := map[string]string{}
	claim := func(ip, id string) {
		a, err := netip.ParseAddr(ip)
		if err != nil || a.IsLoopback() || a.IsUnspecified() {
			return
		}
		ip = a.Unmap().String()
		if prev, ok := owner[ip]; ok && prev != id {
			owner[ip] = "" // ambiguous
			return
		}
		owner[ip] = id
	}
	ids := make([]string, 0, len(agents))
	for id := range agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if hm := metrics[id]; hm != nil && hm.Latest != nil {
			for _, f := range hm.Latest.Ifaces {
				for _, ip := range f.Addrs {
					claim(ip, id)
					if own[ip] && serverHost == "" {
						serverHost = id
					}
				}
			}
		}
	}
	for _, id := range ids {
		if a, err := netip.ParseAddr(agents[id].LastIP); err == nil && a.IsLoopback() && serverHost == "" {
			serverHost = id
		} else if _, ok := owner[agents[id].LastIP]; !ok {
			claim(agents[id].LastIP, id)
		}
	}
	type fk struct {
		from, to string
		port     int
	}
	agg := map[fk]*hostFlow{}
	ext = map[string][2]int{}
	for _, id := range ids {
		hm := metrics[id]
		if hm == nil || hm.Latest == nil || now.Sub(hm.Latest.TS) > metricsStale {
			continue
		}
		in, out := hm.Latest.ConnIn, hm.Latest.ConnOut
		for _, p := range hm.Latest.Peers {
			other := owner[p.IP]
			if other == "" || other == id {
				if a, err := netip.ParseAddr(p.IP); other == id || err == nil && a.IsPrivate() {
					if p.Out {
						out -= p.N
					} else {
						in -= p.N
					}
				}
				continue
			}
			k := fk{other, id, p.Port}
			if p.Out {
				k = fk{id, other, p.Port}
				out -= p.N
			} else {
				in -= p.N
			}
			f := agg[k]
			if f == nil {
				f = &hostFlow{From: k.from, To: k.to, Port: k.port}
				agg[k] = f
			}
			f.N = max(f.N, p.N) // both ends count the same connections
			if p.Out {
				f.ClientProc = p.Process
			} else {
				f.ServerProc = p.Process
			}
		}
		ext[id] = [2]int{max(in, 0), max(out, 0)}
	}
	for _, f := range agg {
		flows = append(flows, *f)
	}
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].From != flows[j].From {
			return flows[i].From < flows[j].From
		}
		if flows[i].To != flows[j].To {
			return flows[i].To < flows[j].To
		}
		return flows[i].Port < flows[j].Port
	})
	return flows, ext, serverHost
}

// handleHosts: GET /api/ui/hosts, every host with its newest load, the
// last hour as sparklines, and the connections between the hosts.
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request, sess *session) {
	s.mu.Lock()
	agents := make(map[string]*AgentRec, len(s.state.Agents))
	views := map[string]agentView{}
	for id, a := range s.state.Agents {
		agents[id] = &AgentRec{ID: a.ID, LastIP: a.LastIP}
		views[id] = s.viewAgent(a)
	}
	s.mu.Unlock()

	s.metrics.mu.Lock()
	snap := make(map[string]*hostMetrics, len(s.metrics.hosts))
	cards := make([]hostCard, 0, len(views))
	cut := time.Now().Add(-time.Hour).Unix()
	for id, v := range views {
		c := hostCard{agentView: v, Spark: []metricPoint{}}
		if hm := s.metrics.hosts[id]; hm != nil {
			snap[id] = &hostMetrics{Latest: hm.Latest}
			if hm.Latest != nil {
				cp := *hm.Latest
				if hm.Last != nil { // the scalars of the newest sample, the lists of the newest detailed one
					d := cp
					cp = *hm.Last
					cp.Disks, cp.Ifaces, cp.Top, cp.Peers = d.Disks, d.Ifaces, d.Top, d.Peers
				}
				c.Metrics = &cp
			}
			for _, p := range hm.Minutes {
				if p.T > cut {
					c.Spark = append(c.Spark, p)
				}
			}
		}
		cards = append(cards, c)
	}
	s.metrics.mu.Unlock()

	now := time.Now()
	flows, ext, serverHost := hostGraph(agents, snap, ownAddrs(s.cfg.AgentListen, s.cfg.Listen), now)
	for i := range cards {
		c := &cards[i]
		c.Stale = c.Metrics != nil && now.Sub(c.Metrics.TS) > metricsStale
		c.Server = c.ID == serverHost
		c.ExtIn, c.ExtOut = ext[c.ID][0], ext[c.ID][1]
	}
	sort.Slice(cards, func(i, j int) bool { return cards[i].Name < cards[j].Name })
	if flows == nil {
		flows = []hostFlow{}
	}
	agentPort := portOf(s.cfg.AgentListen)
	if agentPort == 0 {
		agentPort = portOf(s.cfg.Listen)
	}
	writeJSON(w, map[string]any{"hosts": cards, "flows": flows, "agent_port": agentPort})
}

// handleAgentMetrics: GET /api/ui/agents/{id}/metrics?range=1h|6h|24h|7d|30d
func (s *Server) handleAgentMetrics(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	s.mu.Lock()
	_, ok := s.state.Agents[id]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	spans := map[string]time.Duration{"1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}
	rng := r.URL.Query().Get("range")
	span, ok := spans[rng]
	if !ok {
		rng, span = "6h", 6*time.Hour
	}
	cut := time.Now().Add(-span).Unix()
	out := map[string]any{"range": rng, "step": 60, "points": []metricPoint{}}
	s.metrics.mu.Lock()
	if hm := s.metrics.hosts[id]; hm != nil {
		src := hm.Minutes
		if span > 24*time.Hour {
			src, out["step"] = hm.Hours, 3600
		}
		pts := []metricPoint{}
		for _, p := range src {
			if p.T > cut {
				pts = append(pts, p)
			}
		}
		out["points"] = pts
		out["latest"] = hm.Latest
	}
	s.metrics.mu.Unlock()
	writeJSON(w, out)
}

package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Every five minutes the links between the hosts are kept for the map's
// time slider (flows/<day>.jsonl, eight days), with the first time each
// link (client, server, port) was seen. The same tick checks the active
// plans that ask for it: a link between hosts of the plan that no "allow"
// arrow covers, or that a "block" arrow names, is map.unplanned_link.

const (
	flowEvery = 5 * time.Minute
	flowDays  = 8
)

type flowLite struct {
	F string `json:"f"`
	T string `json:"t"`
	P int    `json:"p"`
	N int    `json:"n"`
}

type flowSnap struct {
	T     int64             `json:"t"`
	Flows []flowLite        `json:"flows"`
	Ext   map[string][2]int `json:"ext,omitempty"`
}

type flowHistory struct {
	mu     sync.Mutex
	last   time.Time
	first  map[string]int64 // "from|to|port" -> unix seconds
	loaded bool
}

func flowDir(dataDir string) string { return filepath.Join(dataDir, "flows") }

func (s *Server) agentPort() int {
	if p := portOf(s.cfg.AgentListen); p != 0 {
		return p
	}
	return portOf(s.cfg.Listen)
}

// graphNow is hostGraph over the newest samples, with the host names.
func (s *Server) graphNow(now time.Time) ([]hostFlow, map[string][2]int, map[string]string) {
	s.mu.Lock()
	agents := make(map[string]*AgentRec, len(s.state.Agents))
	names := map[string]string{}
	for id, a := range s.state.Agents {
		agents[id] = &AgentRec{ID: a.ID, LastIP: a.LastIP}
		names[id] = a.Name
	}
	s.mu.Unlock()
	s.metrics.mu.Lock()
	snap := make(map[string]*hostMetrics, len(s.metrics.hosts))
	for id, hm := range s.metrics.hosts {
		snap[id] = &hostMetrics{Latest: hm.Latest}
	}
	s.metrics.mu.Unlock()
	flows, ext, _, _ := hostGraph(agents, snap, ownAddrs(s.cfg.AgentListen, s.cfg.Listen), now)
	return flows, ext, names
}

// loadFirst reads every kept day once, oldest first.
func (h *flowHistory) loadFirst(dir string) {
	if h.loaded {
		return
	}
	h.loaded = true
	h.first = map[string]int64{}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	sort.Strings(files)
	for _, f := range files {
		readSnaps(f, func(sn flowSnap) {
			for _, fl := range sn.Flows {
				k := fl.F + "|" + fl.T + "|" + strconv.Itoa(fl.P)
				if _, ok := h.first[k]; !ok {
					h.first[k] = sn.T
				}
			}
		})
	}
}

func readSnaps(path string, fn func(flowSnap)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var sn flowSnap
		if json.Unmarshal(sc.Bytes(), &sn) == nil {
			fn(sn)
		}
	}
}

// mapTick runs every minute; it acts every five.
func (s *Server) mapTick(now time.Time) {
	h := &s.flowHist
	h.mu.Lock()
	if now.Sub(h.last) < flowEvery {
		h.mu.Unlock()
		return
	}
	h.last = now
	dir := flowDir(s.cfg.DataDir)
	h.loadFirst(dir)
	flows, ext, names := s.graphNow(now)
	sn := flowSnap{T: now.Unix(), Ext: ext}
	for _, f := range flows {
		sn.Flows = append(sn.Flows, flowLite{f.From, f.To, f.Port, f.N})
		k := f.From + "|" + f.To + "|" + strconv.Itoa(f.Port)
		if _, ok := h.first[k]; !ok {
			h.first[k] = sn.T
		}
	}
	if err := os.MkdirAll(dir, 0o700); err == nil {
		if fh, err := os.OpenFile(filepath.Join(dir, now.UTC().Format("2006-01-02")+".jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			line, _ := json.Marshal(sn)
			fh.Write(append(line, '\n'))
			fh.Close()
		}
		cut := now.UTC().AddDate(0, 0, -flowDays).Format("2006-01-02")
		files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		for _, f := range files {
			if strings.TrimSuffix(filepath.Base(f), ".jsonl") < cut {
				os.Remove(f)
			}
		}
	}
	h.mu.Unlock()
	s.checkUnplanned(flows, names)
}

// handleMapTimeline: GET /api/ui/map/timeline?from=&to= (unix seconds, at
// most eight days), the kept snapshots and when each link was first seen.
func (s *Server) handleMapTimeline(w http.ResponseWriter, r *http.Request, sess *session) {
	now := time.Now()
	to, _ := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	if to <= 0 || to > now.Unix() {
		to = now.Unix()
	}
	if from <= 0 || from >= to || to-from > flowDays*86400 {
		from = to - 86400
	}
	dir := flowDir(s.cfg.DataDir)
	snaps := []flowSnap{}
	for d := time.Unix(from, 0).UTC().Truncate(24 * time.Hour); d.Unix() <= to; d = d.Add(24 * time.Hour) {
		readSnaps(filepath.Join(dir, d.Format("2006-01-02")+".jsonl"), func(sn flowSnap) {
			if sn.T >= from && sn.T <= to {
				snaps = append(snaps, sn)
			}
		})
	}
	s.flowHist.mu.Lock()
	s.flowHist.loadFirst(dir)
	first := make(map[string]int64, len(s.flowHist.first))
	for k, v := range s.flowHist.first {
		first[k] = v
	}
	s.flowHist.mu.Unlock()
	writeJSON(w, map[string]any{"from": from, "to": to, "snaps": snaps, "first_seen": first, "every": int(flowEvery.Seconds())})
}

// planRules are the active plans that alert, as the links they allow and
// block and the hosts they cover.
type planRule struct {
	name    string
	covered map[string]bool
	allow   map[string][]int // "A|B" -> ports, none for any
	block   map[string][]int
}

func arrowPorts(meta map[string]string) []int {
	var out []int
	for _, p := range strings.Split(meta["port"], ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}

func portIn(ports []int, p int) bool {
	if len(ports) == 0 {
		return true
	}
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

func (m *mapStore) planRules() []planRule {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []planRule
	ids := make([]string, 0, len(m.doc.Layers))
	for id := range m.doc.Layers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		l := m.doc.Layers[id]
		if !l.Alert || l.Status != "active" {
			continue
		}
		pr := planRule{name: l.Name, covered: map[string]bool{}, allow: map[string][]int{}, block: map[string][]int{}}
		for _, o := range m.doc.Objects {
			if o.Layer != id || o.Kind != "arrow" || (o.Style != "allow" && o.Style != "block") ||
				!strings.HasPrefix(o.From, "host:") || !strings.HasPrefix(o.To, "host:") {
				continue
			}
			a, b := strings.TrimPrefix(o.From, "host:"), strings.TrimPrefix(o.To, "host:")
			pr.covered[a], pr.covered[b] = true, true
			k := a + "|" + b
			if o.Style == "allow" {
				if _, ok := pr.allow[k]; ok && (len(pr.allow[k]) == 0 || len(arrowPorts(o.Meta)) == 0) {
					pr.allow[k] = nil
				} else {
					pr.allow[k] = append(pr.allow[k], arrowPorts(o.Meta)...)
				}
			} else {
				pr.block[k] = append(pr.block[k], arrowPorts(o.Meta)...)
			}
		}
		out = append(out, pr)
	}
	return out
}

// unplannedFindings: links of the agents to the vigil server always count
// as planned.
func unplannedFindings(rules []planRule, flows []hostFlow, names map[string]string, agentPort int) []struct {
	agent string
	f     finding
} {
	var out []struct {
		agent string
		f     finding
	}
	for _, pr := range rules {
		for _, f := range flows {
			if f.Port == agentPort || !pr.covered[f.From] || !pr.covered[f.To] {
				continue
			}
			k := f.From + "|" + f.To
			blocked := false
			if ps, ok := pr.block[k]; ok && portIn(ps, f.Port) {
				blocked = true
			}
			ps, ok := pr.allow[k]
			if ok && portIn(ps, f.Port) && !blocked {
				continue
			}
			prog := strings.Trim(f.ClientProc+" → "+f.ServerProc, " →")
			if prog == "" {
				prog = "?"
			}
			out = append(out, struct {
				agent string
				f     finding
			}{f.From, finding{Rule: "map.unplanned_link", Key: "map.unplanned_link|" + pr.name + "|" + k + "|" + strconv.Itoa(f.Port),
				Params: map[string]string{"plan": pr.name, "from": names[f.From], "to": names[f.To], "port": strconv.Itoa(f.Port), "program": prog}}})
		}
	}
	return out
}

func (s *Server) checkUnplanned(flows []hostFlow, names map[string]string) {
	rules := s.maps.planRules()
	if len(rules) == 0 {
		return
	}
	fs := unplannedFindings(rules, flows, names, s.agentPort())
	if len(fs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []*Alert
	for _, x := range fs {
		fresh = append(fresh, s.raise([]finding{x.f}, x.agent, 0)...)
	}
	if len(fresh) > 0 {
		s.correlate(fresh)
		s.notifyAlerts(fresh)
		s.saveLocked()
	}
}

// mapAlerts lets the open maps flash the hosts of new alerts.
func (s *Server) mapAlerts(fresh []*Alert) {
	if len(fresh) == 0 || s.maphub == nil {
		return
	}
	out := make([]map[string]string, 0, len(fresh))
	for _, al := range fresh {
		out = append(out, map[string]string{"id": al.ID, "agent": al.Agent, "severity": al.Severity, "rule": al.Rule, "title": al.Title})
	}
	s.maphub.send("alert", out)
}

package server

import (
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Hunting in the past. Threat lists name addresses days after they were
// first used; when a list gains entries, the server looks through the
// stored connections and logins for them (retro hunt). The same scan runs
// on demand for a list of addresses, users and hashes pasted into the
// dashboard.

const (
	retroDays     = 30
	retroSeenKeep = 90 * 24 * time.Hour
	retroMaxHits  = 50
)

// retroFields are the events whose address is a contact made or received.
var retroFields = map[string]string{"net.connection": "remote_ip", "ssh.login": "ip", "web.activity": "ip"}

// retroHunt scans the stored events for addresses on the threat lists that
// were not listed when the event came in. It runs after each intel
// refresh; a hit is reported once per address and list.
func (s *Server) retroHunt() {
	if !s.cfg.ThreatIntel {
		return
	}
	now := time.Now().UTC()
	type hit struct {
		rec  Record
		ip   string
		list string
	}
	var hits []hit
	s.mu.Lock()
	seen := make(map[string]bool, len(s.state.RetroSeen))
	for k, t := range s.state.RetroSeen {
		if now.Sub(t) > retroSeenKeep {
			delete(s.state.RetroSeen, k)
			continue
		}
		seen[k] = true
	}
	// Alerts raised at the time already cover their address.
	for _, al := range s.state.Alerts {
		if strings.HasPrefix(al.Rule, "net.") {
			p := decodeParams(al.Detail)
			if p["ip"] != "" && p["list"] != "" {
				seen[p["ip"]+"|"+p["list"]] = true
			}
		}
	}
	s.mu.Unlock()
	s.store.Between(now.AddDate(0, 0, -retroDays), now, func(rec Record) bool {
		field, ok := retroFields[rec.Event.Type]
		if !ok {
			return true
		}
		ip := str(rec.Event.Data, field)
		if ip == "" {
			return true
		}
		list, listed := s.intel.lookup(ip)
		if !listed || seen[ip+"|"+list] {
			return true
		}
		seen[ip+"|"+list] = true
		hits = append(hits, hit{rec, ip, list})
		return len(hits) < retroMaxHits
	})
	if len(hits) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.RetroSeen == nil {
		s.state.RetroSeen = map[string]time.Time{}
	}
	var fresh []*Alert
	for _, h := range hits {
		s.state.RetroSeen[h.ip+"|"+h.list] = now
		a := s.state.Agents[h.rec.Agent]
		if a == nil {
			continue
		}
		d := h.rec.Event.Data
		proc := str(d, "process")
		if proc == "" {
			proc = map[string]string{"ssh.login": "sshd (login as " + str(d, "user") + ")", "web.activity": "web server"}[h.rec.Event.Type]
		}
		f := finding{Rule: "net.retro_hit", Key: "net.retro_hit|" + a.ID + "|" + h.ip + "|" + h.list, Params: map[string]string{
			"host": a.Name, "ip": h.ip, "list": h.list, "process": proc, "when": recordTime(h.rec).Format("2006-01-02 15:04 UTC"),
			"event": h.rec.Event.Type, "seq": strconv.FormatUint(h.rec.Seq, 10)}}
		fresh = append(fresh, s.raise([]finding{f}, a.ID, h.rec.Seq)...)
	}
	s.saveLocked()
	s.notifyAlerts(fresh)
}

// POST /api/ui/hunt {"values": ["1.2.3.4", "root", "<sha256>"], "days": 30}
func (s *Server) handleHunt(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Values []string `json:"values"`
		Days   int      `json:"days"`
	}
	if !decode(r, w, &req) {
		return
	}
	if req.Days <= 0 {
		req.Days = 30
	}
	if max := s.cfg.RetentionDays; max > 0 && req.Days > max {
		req.Days = max
	}
	if req.Days > pivotDaysMax {
		req.Days = pivotDaysMax
	}
	type result struct {
		Kind  string         `json:"kind"`
		Value string         `json:"value"`
		Count int            `json:"count"`
		First time.Time      `json:"first,omitempty"`
		Last  time.Time      `json:"last,omitempty"`
		Hosts map[string]int `json:"hosts"`
		Intel string         `json:"intel,omitempty"`
	}
	want := map[string]*result{}
	var invalid []string
	for _, v := range req.Values {
		v = strings.TrimSpace(v)
		if v == "" || len(want) >= 500 {
			continue
		}
		k := ""
		switch {
		case validIP(v):
			v, k = netip.MustParseAddr(v).String(), "ip"
		case validHash(strings.ToLower(v)):
			v, k = strings.ToLower(v), "hash"
		case validUser(v):
			k = "user"
		default:
			invalid = append(invalid, v)
			continue
		}
		res := &result{Kind: k, Value: v, Hosts: map[string]int{}}
		if k == "ip" {
			res.Intel, _ = s.intel.lookup(v)
		}
		want[k+"|"+v] = res
	}
	if len(want) == 0 {
		http.Error(w, "no address, user or SHA-256 hash in the list", http.StatusBadRequest)
		return
	}
	names := s.agentNames()
	now := time.Now().UTC()
	deadline := time.Now().Add(scanBudget)
	partial := false
	s.store.Between(now.AddDate(0, 0, -req.Days), now, func(rec Record) bool {
		if time.Now().After(deadline) {
			partial = true
			return false
		}
		for _, e := range entities(rec.Event) {
			res := want[e.Kind+"|"+e.Value]
			if res == nil {
				continue
			}
			t := recordTime(rec)
			res.Count++
			res.Hosts[names[rec.Agent]]++
			if res.First.IsZero() || t.Before(res.First) {
				res.First = t
			}
			if t.After(res.Last) {
				res.Last = t
			}
		}
		return true
	})
	out := make([]*result, 0, len(want))
	for _, r := range want {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	s.audit(sess.User, "admin.hunt", map[string]any{"values": len(want), "days": req.Days})
	writeJSON(w, map[string]any{"results": out, "invalid": invalid, "days": req.Days, "partial": partial})
}

// ---------- SSH sessions ----------

type sessionView struct {
	Agent    string     `json:"agent"`
	Host     string     `json:"host"`
	PID      int        `json:"sshd_pid"`
	User     string     `json:"user"`
	IP       string     `json:"ip"`
	Method   string     `json:"method"`
	Key      string     `json:"key,omitempty"`
	Start    time.Time  `json:"start"`
	End      *time.Time `json:"end,omitempty"`
	Commands int        `json:"commands"`
	Sudo     int        `json:"sudo"`
	Files    int        `json:"files"`
	Alerts   int        `json:"alerts"`
	Dropped  int        `json:"dropped,omitempty"`
}

// sshSessions rebuilds SSH sessions from logins, logouts, session commands,
// sudo and file changes. A session is a login (agent and sshd process),
// open until the logout of the same process or the next login with it.
func (s *Server) sshSessions(agent string, from, to time.Time) ([]*sessionView, map[string][]viewRecord) {
	names := s.agentNames()
	byKey := map[string]*sessionView{}
	var order []*sessionView
	open := map[string]*sessionView{} // agent|pid -> open session
	openUser := map[string][]*sessionView{}
	events := map[string][]viewRecord{}
	key := func(v *sessionView) string {
		return v.Agent + "|" + strconv.Itoa(v.PID) + "|" + v.Start.Format(time.RFC3339Nano)
	}
	s.store.Between(from.Add(-24*time.Hour), to, func(rec Record) bool {
		if agent != "" && rec.Agent != agent {
			return true
		}
		d := rec.Event.Data
		t := recordTime(rec)
		ak := rec.Agent + "|" + str(d, "sshd_pid")
		switch rec.Event.Type {
		case "ssh.login":
			v := &sessionView{Agent: rec.Agent, Host: names[rec.Agent], PID: int(num(d, "sshd_pid")), User: str(d, "user"), IP: str(d, "ip"),
				Method: str(d, "method"), Key: str(d, "key_comment"), Start: t}
			if v.Key == "" {
				v.Key = str(d, "fingerprint")
			}
			open[ak] = v
			openUser[rec.Agent+"|"+v.User] = append(openUser[rec.Agent+"|"+v.User], v)
			byKey[key(v)] = v
			if !t.Before(from) {
				order = append(order, v)
			}
		case "ssh.logout":
			if v := open[ak]; v != nil {
				e := t
				v.End = &e
				delete(open, ak)
			}
		case "session.exec", "session.dropped":
			v := open[ak]
			if v == nil {
				return true
			}
			if rec.Event.Type == "session.dropped" {
				v.Dropped += int(num(d, "count"))
				return true
			}
			v.Commands++
			if k := key(v); len(events[k]) < 2000 {
				events[k] = append(events[k], viewRecord{Record: rec, Host: v.Host})
			}
		case "sudo.command":
			// sudo logs the user, not the session: the newest open session
			// of that user on the host.
			list := openUser[rec.Agent+"|"+str(d, "user")]
			for i := len(list) - 1; i >= 0; i-- {
				if v := list[i]; v.End == nil || !t.After(*v.End) {
					v.Sudo++
					k := key(v)
					events[k] = append(events[k], viewRecord{Record: rec, Host: v.Host})
					break
				}
			}
		case "file.added", "file.changed", "file.removed":
			// Changed while a session was open; not proof that it did it.
			for _, v := range open {
				if v.Agent == rec.Agent {
					v.Files++
					k := key(v)
					events[k] = append(events[k], viewRecord{Record: rec, Host: v.Host})
				}
			}
		}
		return true
	})
	s.mu.Lock()
	for _, v := range order {
		end := time.Now().UTC()
		if v.End != nil {
			end = *v.End
		}
		for _, al := range s.state.Alerts {
			if al.Agent == v.Agent && !al.Created.Before(v.Start) && !al.Created.After(end.Add(2*time.Minute)) {
				v.Alerts++
			}
		}
	}
	s.mu.Unlock()
	// newest first
	sort.SliceStable(order, func(i, j int) bool { return order[i].Start.After(order[j].Start) })
	_ = byKey
	return order, events
}

// GET /api/ui/sessions?agent=&days=
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request, sess *session) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 90 {
		days = 7
	}
	now := time.Now().UTC()
	list, _ := s.sshSessions(r.URL.Query().Get("agent"), now.AddDate(0, 0, -days), now)
	if len(list) > 500 {
		list = list[:500]
	}
	if list == nil {
		list = []*sessionView{}
	}
	writeJSON(w, map[string]any{"sessions": list, "days": days})
}

// GET /api/ui/session?agent=&pid=&start=
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	agent := q.Get("agent")
	pid, _ := strconv.Atoi(q.Get("pid"))
	start, err := time.Parse(time.RFC3339Nano, q.Get("start"))
	if agent == "" || pid <= 0 || err != nil {
		http.Error(w, "agent, pid and start needed", http.StatusBadRequest)
		return
	}
	list, events := s.sshSessions(agent, start.Add(-time.Second), start.Add(7*24*time.Hour))
	for _, v := range list {
		if v.PID == pid && v.Start.Equal(start) {
			evs := events[v.Agent+"|"+strconv.Itoa(v.PID)+"|"+v.Start.Format(time.RFC3339Nano)]
			names := s.agentNames()
			role := s.rolesFor(sess)
			out := make([]viewRecord, len(evs))
			for i, e := range evs {
				out[i] = s.view(e.Record, names, role)
			}
			alerts := []alertView{}
			end := time.Now().UTC()
			if v.End != nil {
				end = *v.End
			}
			s.mu.Lock()
			for _, al := range s.state.Alerts {
				if al.Agent == v.Agent && !al.Created.Before(v.Start) && !al.Created.After(end.Add(2*time.Minute)) {
					alerts = append(alerts, s.viewAlert(al, lang(r)))
				}
			}
			s.mu.Unlock()
			writeJSON(w, map[string]any{"session": v, "events": out, "alerts": alerts})
			return
		}
	}
	http.NotFound(w, r)
}

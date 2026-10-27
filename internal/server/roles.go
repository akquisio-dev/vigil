package server

import (
	"errors"
	"net/http"
	"strings"
)

// Roles per group. An account has its base role for the whole network and
// may have a higher one for groups of hosts: Moritz can be viewer
// everywhere and admin of the group "Moritz". For anything tied to one host
// (its alerts, incidents, canaries, actions, the host itself) the higher of
// the two counts; everything that concerns the whole network (accounts,
// sources, shares, rules, suppressions, enrolling hosts, searching the
// whole log) needs the base role.

type roleSet struct {
	base   string
	groups map[string]string   // lower case group -> role
	tags   map[string][]string // agent -> its groups
}

// For is the role for one host; "" (records of the server itself) gets
// the base role.
func (rs roleSet) For(agent string) string {
	best := rs.base
	for _, t := range rs.tags[agent] {
		if r := rs.groups[strings.ToLower(t)]; roleRank[r] > roleRank[best] {
			best = r
		}
	}
	return best
}

func groupRoles(u *User) map[string]string {
	out := map[string]string{}
	for g, r := range u.GroupRoles {
		if roleRank[r] > 0 {
			out[strings.ToLower(g)] = r
		}
	}
	return out
}

// rolesFor takes s.mu for a moment: callers must not hold it.
func (s *Server) rolesFor(sess *session) roleSet {
	rs := roleSet{base: "viewer"}
	u := s.user(sess.User)
	if u == nil {
		return rs
	}
	rs.base, rs.groups = roleOf(u), groupRoles(u)
	if len(rs.groups) == 0 {
		return rs
	}
	s.mu.Lock()
	rs.tags = make(map[string][]string, len(s.state.Agents))
	for id, a := range s.state.Agents {
		rs.tags[id] = append([]string{}, a.Tags...)
	}
	s.mu.Unlock()
	return rs
}

// rolesLocked is rolesFor for a caller that holds s.mu.
func (s *Server) rolesLocked(sess *session) roleSet {
	rs := roleSet{base: "viewer"}
	u := s.user(sess.User)
	if u == nil {
		return rs
	}
	rs.base, rs.groups = roleOf(u), groupRoles(u)
	if len(rs.groups) > 0 {
		rs.tags = make(map[string][]string, len(s.state.Agents))
		for id, a := range s.state.Agents {
			rs.tags[id] = a.Tags
		}
	}
	return rs
}

// mayHost tells whether the account has at least need for every one of
// the hosts; an unknown host ("" included) needs the base role.
func (rs roleSet) mayHost(need string, agents ...string) bool {
	for _, a := range agents {
		if roleRank[rs.For(a)] < roleRank[need] {
			return false
		}
	}
	return len(agents) > 0 || roleRank[rs.base] >= roleRank[need]
}

func forbidden(w http.ResponseWriter, role string) {
	http.Error(w, "your role ("+role+") does not allow this on this host", http.StatusForbidden)
}

// allowHost answers 403 and returns false unless the account has need on
// the host. Caller must not hold s.mu.
func (s *Server) allowHost(w http.ResponseWriter, sess *session, need, agent string) bool {
	rs := s.rolesFor(sess)
	if rs.mayHost(need, agent) {
		return true
	}
	forbidden(w, rs.For(agent))
	return false
}

// hostOf finds the host an object belongs to. Caller holds s.mu.
func (s *Server) alertAgentLocked(id string) (string, bool) {
	for _, al := range s.state.Alerts {
		if al.ID == id {
			return al.Agent, true
		}
	}
	return "", false
}

// onHost guards a route tied to one host: signed in (and the CSRF token
// for changes) like auth, then need on the host that resolve names.
// resolve returns false for an object that does not exist (404).
func (s *Server) onHost(need string, resolve func(*http.Request) (string, bool), h authed) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request, sess *session) {
		s.mu.Lock()
		agent, ok := resolve(r)
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if !s.allowHost(w, sess, need, agent) {
			return
		}
		h(w, r, sess)
	})
}

// Resolvers for onHost; they run under s.mu.
func (s *Server) hostByAgent(r *http.Request) (string, bool) {
	id := r.PathValue("id")
	_, ok := s.state.Agents[id]
	return id, ok
}

func (s *Server) hostByAlert(r *http.Request) (string, bool) {
	return s.alertAgentLocked(r.PathValue("id"))
}

func (s *Server) hostByIncident(r *http.Request) (string, bool) {
	if c := s.incident(r.PathValue("id")); c != nil {
		return c.Agent, true
	}
	return "", false
}

func (s *Server) hostByCanary(r *http.Request) (string, bool) {
	if c := s.state.Canaries[r.PathValue("id")]; c != nil {
		return c.AgentID, true
	}
	return "", false
}

func (s *Server) hostByAction(r *http.Request) (string, bool) {
	for _, a := range s.state.Actions {
		if a.ID == r.PathValue("id") {
			return a.Agent, true
		}
	}
	return "", false
}

// cleanGroupRoles checks the roles an admin gives an account per group:
// group names like host tags, roles viewer, analyst or admin, at most 16.
func cleanGroupRoles(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for g, r := range in {
		g = strings.TrimSpace(g)
		if t := cleanTags([]string{g}); len(t) != 1 {
			return nil, errors.New("bad group name: " + g)
		}
		if roleRank[r] == 0 {
			return nil, errors.New("role must be viewer, analyst or admin")
		}
		out[g] = r
	}
	if len(out) > 16 {
		return nil, errors.New("at most 16 groups per account")
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

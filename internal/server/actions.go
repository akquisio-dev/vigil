package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// ActionRec is a response action an admin started. It reaches the agent in
// the next signed configuration and is valid for ten minutes.
type ActionRec struct {
	ID      string            `json:"id"`
	Agent   string            `json:"agent"`
	Type    string            `json:"type"`
	Params  map[string]string `json:"params"`
	Alert   string            `json:"alert,omitempty"`
	By      string            `json:"by"`
	Created time.Time         `json:"created"`
	Expires time.Time         `json:"expires"`
	Status  string            `json:"status"` // approval | pending | done | failed | expired | rejected
	Result  string            `json:"result,omitempty"`
	// Four-eyes: the second person who released the action.
	ApprovedBy string     `json:"approved_by,omitempty"`
	Approved   *time.Time `json:"approved,omitempty"`
	// Playbook names the automatic run that created it.
	Playbook string `json:"playbook,omitempty"`
}

const (
	actionTTL   = 10 * time.Minute
	approvalTTL = 30 * time.Minute
)

var accountName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

func minutesParam(p map[string]string, max int) error {
	if p["minutes"] == "" {
		return nil
	}
	if m, err := strconv.Atoi(p["minutes"]); err != nil || m < 1 || m > max {
		return fmt.Errorf("minutes must be 1 to %d", max)
	}
	return nil
}

func validAction(t string, p map[string]string) error {
	switch t {
	case "block_ip":
		ip := net.ParseIP(p["ip"])
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			return errors.New("block_ip needs a public address")
		}
		if m, err := strconv.Atoi(p["minutes"]); p["minutes"] != "" && (err != nil || m < 1 || m > 30*24*60) {
			return errors.New("minutes must be 1 to 43200")
		}
	case "kill_session":
		if n, err := strconv.Atoi(p["sshd_pid"]); err != nil || n <= 1 {
			return errors.New("kill_session needs the sshd pid")
		}
	case "kill_process":
		if n, err := strconv.Atoi(p["pid"]); err != nil || n <= 1 || !strings.HasPrefix(p["exe"], "/") {
			return errors.New("kill_process needs pid and exe")
		}
	case "remove_key":
		if !strings.HasSuffix(p["file"], "/authorized_keys") && !strings.HasSuffix(p["file"], "/authorized_keys2") || !strings.HasPrefix(p["fingerprint"], "SHA256:") {
			return errors.New("remove_key needs an authorized_keys file and a fingerprint")
		}
	case "isolate_host":
		return minutesParam(p, 24*60)
	case "release_host":
	case "lock_user", "unlock_user":
		if !accountName.MatchString(p["user"]) || p["user"] == "root" {
			return errors.New(t + " needs a user name other than root")
		}
		if t == "lock_user" {
			return minutesParam(p, 30*24*60)
		}
	default:
		return errors.New("unknown action")
	}
	return nil
}

// suggestActions lists what can be done about an alert, from its parameters
// and the events behind it. The caller holds s.mu.
func (s *Server) suggestActions(al *Alert) []proto.Action {
	p := decodeParams(al.Detail)
	var out []proto.Action
	add := func(t string, params map[string]string) {
		if validAction(t, params) == nil {
			out = append(out, proto.Action{Type: t, Params: params})
		}
	}
	if ip := p["ip"]; ip != "" {
		add("block_ip", map[string]string{"ip": ip, "minutes": "1440"})
	}
	if strings.HasPrefix(al.Rule, "ssh.") && al.Rule != "ssh.key_added" && al.Rule != "ssh.key_removed" {
		seqs := map[uint64]bool{}
		for _, q := range al.Seqs {
			seqs[q] = true
		}
		s.store.Each(func(rec Record) {
			if seqs[rec.Seq] && rec.Event.Type == "ssh.login" {
				add("kill_session", map[string]string{"sshd_pid": str(rec.Event.Data, "sshd_pid"), "user": str(rec.Event.Data, "user")})
			}
		})
	}
	if strings.HasPrefix(al.Rule, "process.") {
		add("kill_process", map[string]string{"pid": p["pid"], "exe": p["exe"]})
	}
	if al.Rule == "ssh.key_added" {
		add("remove_key", map[string]string{"file": p["file"], "fingerprint": p["fingerprint"]})
	}
	if u := p["user"]; u != "" && (strings.HasPrefix(al.Rule, "ssh.") || strings.HasPrefix(al.Rule, "user.")) {
		add("lock_user", map[string]string{"user": u, "minutes": "1440"})
	}
	if al.Agent != "" && severityRank[al.Severity] >= severityRank["high"] && autoSnapshotRule(al.Rule) {
		add("isolate_host", map[string]string{"minutes": "60"})
	}
	return out
}

// needsApproval tells whether a second person must release an action type.
func (s *Server) needsApproval(t string) bool {
	for _, x := range s.cfg.FourEyes {
		if x == t || x == "*" {
			return true
		}
	}
	return false
}

// queueAction records an action; with four-eyes it waits for approval.
// Caller holds s.mu.
func (s *Server) queueAction(a *AgentRec, typ string, params map[string]string, alert, by, playbook string) *ActionRec {
	now := time.Now().UTC()
	clean := map[string]string{}
	for k, v := range params {
		clean[cleanParam(k)] = cleanParam(v)
	}
	act := &ActionRec{ID: newID(8), Agent: a.ID, Type: typ, Params: clean, Alert: alert, By: by, Playbook: playbook,
		Created: now, Expires: now.Add(actionTTL), Status: "pending"}
	if s.needsApproval(typ) {
		act.Status, act.Expires = "approval", now.Add(approvalTTL)
	} else {
		a.ConfigVersion++
	}
	s.state.Actions = append(s.state.Actions, act)
	if over := len(s.state.Actions) - 500; over > 0 {
		s.state.Actions = append([]*ActionRec{}, s.state.Actions[over:]...)
	}
	return act
}

// POST /api/ui/actions/{id}/approve {"code": "123456"} and .../reject
func (s *Server) handleActionDecision(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(r, w, &req) {
		return
	}
	decision := r.PathValue("decision")
	if decision != "approve" && decision != "reject" {
		http.NotFound(w, r)
		return
	}
	if err := s.reauth(sess.User, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.mu.Lock()
	var act *ActionRec
	for _, x := range s.state.Actions {
		if x.ID == r.PathValue("id") {
			act = x
		}
	}
	switch {
	case act == nil:
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	case act.Status != "approval":
		s.mu.Unlock()
		http.Error(w, "this action is not waiting for approval", http.StatusConflict)
		return
	case time.Now().After(act.Expires):
		act.Status, act.Result = "expired", "nobody approved it in time"
		s.saveLocked()
		s.mu.Unlock()
		http.Error(w, "expired", http.StatusConflict)
		return
	case decision == "approve" && act.By == sess.User:
		s.mu.Unlock()
		http.Error(w, "four-eyes: a second person has to approve", http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	act.ApprovedBy, act.Approved = sess.User, &now
	if decision == "approve" {
		act.Status, act.Expires = "pending", now.Add(actionTTL)
		if a := s.state.Agents[act.Agent]; a != nil {
			a.ConfigVersion++
		}
	} else {
		act.Status, act.Result = "rejected", "rejected by "+sess.User
	}
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "response."+decision+"d", map[string]any{"action": act.ID, "agent": act.Agent, "type": act.Type, "requested_by": act.By})
	writeJSON(w, act)
}

func (s *Server) handleAlertActions(w http.ResponseWriter, r *http.Request, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	al := s.alertByID(r.PathValue("id"))
	if al == nil {
		http.NotFound(w, r)
		return
	}
	allowed := []string{}
	if a := s.state.Agents[al.Agent]; a != nil {
		allowed = a.ResponseTypes
	}
	suggested := s.suggestActions(al)
	if suggested == nil {
		suggested = []proto.Action{}
	}
	writeJSON(w, map[string]any{"suggested": suggested, "allowed": allowed})
}

func (s *Server) handleRespond(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Type   string            `json:"type"`
		Params map[string]string `json:"params"`
		Alert  string            `json:"alert"`
		Code   string            `json:"code"`
	}
	if !decode(r, w, &req) {
		return
	}
	if err := validAction(req.Type, req.Params); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.reauth(sess.User, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.mu.Lock()
	a := s.state.Agents[r.PathValue("id")]
	if a == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	act := s.queueAction(a, req.Type, req.Params, req.Alert, sess.User, "")
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "response.requested", map[string]any{"action": act.ID, "agent": a.ID, "type": act.Type, "params": act.Params, "alert": req.Alert})
	writeJSON(w, act)
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request, sess *session) {
	agent := r.URL.Query().Get("agent")
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*ActionRec{}
	for i := len(s.state.Actions) - 1; i >= 0 && len(out) < 100; i-- {
		if act := s.state.Actions[i]; agent == "" || act.Agent == agent {
			if act.Status == "pending" && time.Since(act.Expires) > time.Minute {
				act.Status, act.Result = "expired", "the agent did not pick it up in time"
			}
			if act.Status == "approval" && time.Now().After(act.Expires) {
				act.Status, act.Result = "expired", "nobody approved it in time"
			}
			out = append(out, act)
		}
	}
	writeJSON(w, out)
}

// pendingActions are the actions an agent still has to see. The caller holds s.mu.
func (s *Server) pendingActions(agentID string) []proto.Action {
	var out []proto.Action
	now := time.Now()
	for _, act := range s.state.Actions {
		if act.Agent == agentID && act.Status == "pending" && now.Before(act.Expires) {
			out = append(out, proto.Action{ID: act.ID, Type: act.Type, Params: act.Params, Expires: act.Expires})
		}
	}
	return out
}

// actionResult records what the agent reported. The caller holds s.mu.
func (s *Server) actionResult(agentID string, d map[string]any) {
	id := str(d, "action_id")
	for _, act := range s.state.Actions {
		if act.ID == id && act.Agent == agentID {
			act.Status = "failed"
			act.Result = str(d, "error")
			if ok, _ := d["ok"].(bool); ok {
				act.Status, act.Result = "done", str(d, "detail")
			}
		}
	}
}

package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Evidence snapshots. Agents take one on their own for their strongest
// signals; the server asks for one when a high or critical alert about
// activity on a host is raised, and an analyst can ask from the dashboard.
// The snapshot itself is an agent event (forensics.snapshot) and lives in
// the event log; the server keeps a short index per host to list them.

const (
	snapshotExpiry   = 10 * time.Minute
	snapshotAutoGap  = 10 * time.Minute // between automatic requests per host
	snapshotRecent   = 2 * time.Minute  // a snapshot the agent took itself counts this long
	snapshotIndexMax = 200
)

type SnapshotReq struct {
	ID      string    `json:"id"`
	Agent   string    `json:"agent"`
	Alert   string    `json:"alert,omitempty"`
	PID     int       `json:"pid,omitempty"`
	By      string    `json:"by"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Status  string    `json:"status"` // pending | done | failed | expired
	Seq     uint64    `json:"seq,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// SnapshotRef points to one snapshot in the event log.
type SnapshotRef struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	Trigger string    `json:"trigger"`
	PID     int       `json:"pid,omitempty"`
	Comm    string    `json:"comm,omitempty"`
	Exe     string    `json:"exe,omitempty"`
	SHA256  string    `json:"exe_sha256,omitempty"`
	Alert   string    `json:"alert,omitempty"`
	Request string    `json:"request,omitempty"`
	Error   string    `json:"error,omitempty"`
	Hash    string    `json:"sha256,omitempty"`
}

// No snapshot for conditions and for vigil's own health: they describe a
// state, not something a process is doing right now.
var noSnapshotPrefixes = []string{"posture.", "tls.", "backup.", "vuln.", "updates.", "secret.", "agent.", "notify.", "selftest.", "chain.", "integrity.many"}

func autoSnapshotRule(rule string) bool {
	for _, p := range noSnapshotPrefixes {
		if strings.HasPrefix(rule, p) {
			return false
		}
	}
	return true
}

// requestSnapshot queues a request for the agent. Caller holds s.mu.
func (s *Server) requestSnapshot(a *AgentRec, alert string, pid int, by string) *SnapshotReq {
	now := time.Now().UTC()
	req := &SnapshotReq{ID: newID(8), Agent: a.ID, Alert: alert, PID: pid, By: by, Created: now, Expires: now.Add(snapshotExpiry), Status: "pending"}
	s.state.Snapshots = append(s.state.Snapshots, req)
	if over := len(s.state.Snapshots) - 500; over > 0 {
		s.state.Snapshots = append([]*SnapshotReq{}, s.state.Snapshots[over:]...)
	}
	a.ConfigVersion++
	return req
}

// autoSnapshots asks for a snapshot for new high and critical alerts about
// activity, at most once per host every ten minutes, and not when the agent
// just took one itself. Caller holds s.mu.
func (s *Server) autoSnapshots(fresh []*Alert) {
	now := time.Now().UTC()
	for _, al := range fresh {
		a := s.state.Agents[al.Agent]
		if a == nil || !a.Forensics || severityRank[al.Severity] < severityRank["high"] || !autoSnapshotRule(al.Rule) {
			continue
		}
		if now.Sub(a.LastSnapshot) < snapshotRecent || now.Sub(a.LastSnapshotAsk) < snapshotAutoGap {
			continue
		}
		pid, _ := strconv.Atoi(decodeParams(al.Detail)["pid"])
		a.LastSnapshotAsk = now
		s.requestSnapshot(a, al.ID, pid, "system")
	}
}

func (s *Server) pendingSnapshots(agentID string) []proto.SnapshotRequest {
	var out []proto.SnapshotRequest
	now := time.Now()
	for _, r := range s.state.Snapshots {
		if r.Agent == agentID && r.Status == "pending" && now.Before(r.Expires) {
			out = append(out, proto.SnapshotRequest{ID: r.ID, PID: r.PID, Alert: r.Alert, Expires: r.Expires})
		}
	}
	return out
}

// snapshotReceived indexes a snapshot event. Caller holds s.mu.
func (s *Server) snapshotReceived(a *AgentRec, rec *Record) {
	d := rec.Event.Data
	ref := SnapshotRef{Seq: rec.Seq, Time: recordTime(*rec), Trigger: str(d, "trigger"), PID: int(num(d, "pid")),
		Alert: str(d, "alert"), Request: str(d, "request"), Error: str(d, "error"), Hash: str(d, "sha256")}
	if t, ok := d["target"].(map[string]any); ok {
		ref.Comm, ref.Exe, ref.SHA256 = str(t, "comm"), str(t, "exe"), str(t, "exe_sha256")
	}
	if ref.Trigger == "" && ref.Request != "" {
		ref.Trigger = "request"
	}
	if ref.Error == "" {
		a.LastSnapshot = time.Now().UTC()
	}
	a.SnapshotIndex = append(a.SnapshotIndex, ref)
	if over := len(a.SnapshotIndex) - snapshotIndexMax; over > 0 {
		a.SnapshotIndex = append([]SnapshotRef{}, a.SnapshotIndex[over:]...)
	}
	for _, r := range s.state.Snapshots {
		if r.ID == ref.Request && r.Agent == a.ID && r.Status == "pending" {
			r.Seq = rec.Seq
			if ref.Error != "" {
				r.Status, r.Error = "failed", ref.Error
			} else {
				r.Status = "done"
			}
		}
	}
}

// expireSnapshots marks requests the agent never answered. Caller holds s.mu.
func (s *Server) expireSnapshots() {
	now := time.Now()
	for _, r := range s.state.Snapshots {
		if r.Status == "pending" && now.After(r.Expires.Add(time.Minute)) {
			r.Status, r.Error = "expired", "the agent did not answer in time"
		}
	}
}

// GET /api/ui/snapshots?agent=&alert=
func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request, sess *session) {
	agent, alert := r.URL.Query().Get("agent"), r.URL.Query().Get("alert")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireSnapshots()
	refs := []SnapshotRef{}
	reqs := []*SnapshotReq{}
	for id, a := range s.state.Agents {
		if agent != "" && id != agent {
			continue
		}
		for i := len(a.SnapshotIndex) - 1; i >= 0; i-- {
			ref := a.SnapshotIndex[i]
			if alert == "" || ref.Alert == alert {
				refs = append(refs, ref)
			}
		}
	}
	for i := len(s.state.Snapshots) - 1; i >= 0; i-- {
		rq := s.state.Snapshots[i]
		if (agent == "" || rq.Agent == agent) && (alert == "" || rq.Alert == alert) && len(reqs) < 50 {
			reqs = append(reqs, rq)
		}
	}
	writeJSON(w, map[string]any{"snapshots": refs, "requests": reqs})
}

// POST /api/ui/agents/{id}/snapshot {"alert": "...", "pid": 123}
func (s *Server) handleSnapshotRequest(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Alert string `json:"alert"`
		PID   int    `json:"pid"`
	}
	body, err := readBody(w, r)
	if err == nil && len(body) > 0 {
		err = json.Unmarshal(body, &req)
	}
	if err != nil || req.PID < 0 || len(req.Alert) > 64 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	a := s.state.Agents[r.PathValue("id")]
	if a == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if !a.Forensics {
		s.mu.Unlock()
		http.Error(w, "this host does not take snapshots (forensics in agent.json, or an agent older than v0.14.0)", http.StatusConflict)
		return
	}
	if req.PID == 0 && req.Alert != "" {
		for _, al := range s.state.Alerts {
			if al.ID == req.Alert {
				req.PID, _ = strconv.Atoi(decodeParams(al.Detail)["pid"])
			}
		}
	}
	rq := s.requestSnapshot(a, req.Alert, req.PID, sess.User)
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "forensics.requested", map[string]any{"agent": a.ID, "alert": req.Alert, "pid": req.PID, "request": rq.ID})
	writeJSON(w, rq)
}

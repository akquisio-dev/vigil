package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func forensicServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenStore(dir+"/events", 100)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: &Config{DataDir: dir, RetentionDays: 90}, store: st,
		state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	s.state.Agents["a1"] = &AgentRec{ID: "a1", Name: "web", Forensics: true}
	s.state.Agents["a2"] = &AgentRec{ID: "a2", Name: "game"}
	return s
}

func appendAt(t *testing.T, s *Server, agent string, ts time.Time, typ string, d map[string]any) *Record {
	t.Helper()
	rec := &Record{Agent: agent, Source: "agent", Event: proto.Event{Type: typ, TS: ts, Data: d}}
	if err := s.store.Append(rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func getJSON(t *testing.T, h http.HandlerFunc, url string, sess *session, out any) int {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("GET", url, nil))
	if w.Code == 200 {
		json.Unmarshal(w.Body.Bytes(), out)
	}
	return w.Code
}

func TestTimelineAndPivot(t *testing.T) {
	s := forensicServer(t)
	if err := SaveUsers(s.cfg.DataDir, map[string]*User{"ana": {Name: "ana", Role: "analyst"}, "vic": {Name: "vic", Role: "viewer"}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	appendAt(t, s, "a1", now.Add(-2*time.Hour), "ssh.login", map[string]any{"user": "root", "ip": "203.0.113.7"})
	login := appendAt(t, s, "a1", now.Add(-20*time.Minute), "ssh.login", map[string]any{"user": "deploy", "ip": "203.0.113.7"})
	appendAt(t, s, "a1", now.Add(-10*time.Minute), "file.changed", map[string]any{"path": "/etc/sudoers", "diff": "+evil ALL=(ALL) NOPASSWD: ALL\n"})
	appendAt(t, s, "a2", now.Add(-10*time.Minute), "net.connection", map[string]any{"remote_ip": "203.0.113.7", "process": "curl"})
	// late arrival: happened 5 minutes ago, received now
	appendAt(t, s, "a1", now.Add(-5*time.Minute), "integrity.mismatch", map[string]any{"path": "/usr/sbin/sshd", "sha256": strings.Repeat("ab", 32)})
	s.state.Alerts = append(s.state.Alerts, &Alert{ID: "al1", Agent: "a1", Rule: "ssh.new_source", Severity: "medium", Created: now,
		Seqs: []uint64{login.Seq}, Detail: "ip=203.0.113.7\nuser=deploy\n", Status: "open"})

	ana := &session{User: "ana"}
	vic := &session{User: "vic"}
	h := func(sess *session, fn authed) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { fn(w, r, sess) }
	}

	var tl struct {
		At      time.Time    `json:"at"`
		Records []viewRecord `json:"records"`
		Alerts  []alertView  `json:"alerts"`
	}
	if c := getJSON(t, h(ana, s.handleTimeline), "/api/ui/timeline?alert=al1&minutes=30", ana, &tl); c != 200 {
		t.Fatalf("timeline %d", c)
	}
	if !tl.At.Equal(login.Event.TS) {
		t.Fatalf("anchored on the event, not the alert: %v", tl.At)
	}
	var types []string
	for _, r := range tl.Records {
		types = append(types, r.Event.Type)
	}
	if strings.Join(types, ",") != "ssh.login,file.changed,integrity.mismatch" {
		t.Fatalf("timeline: %v", types)
	}
	if tl.Records[1].Event.Data["diff"] == "(analyst role needed)" {
		t.Fatal("analysts see diffs")
	}
	getJSON(t, h(vic, s.handleTimeline), "/api/ui/timeline?alert=al1", vic, &tl)
	if tl.Records[1].Event.Data["diff"] != "(analyst role needed)" {
		t.Fatalf("viewers do not: %v", tl.Records[1].Event.Data)
	}

	var pv struct {
		Total   int            `json:"total"`
		Hosts   map[string]int `json:"hosts"`
		Records []viewRecord   `json:"records"`
		Alerts  []alertView    `json:"alerts"`
		Public  bool           `json:"public"`
	}
	getJSON(t, h(ana, s.handlePivot), "/api/ui/pivot?kind=ip&value=203.0.113.7", ana, &pv)
	if pv.Total != 3 || pv.Hosts["web"] != 2 || pv.Hosts["game"] != 1 || len(pv.Alerts) != 1 || pv.Records[0].Event.Type != "net.connection" {
		t.Fatalf("ip pivot: %+v", pv)
	}
	getJSON(t, h(ana, s.handlePivot), "/api/ui/pivot?kind=user&value=deploy", ana, &pv)
	if pv.Total != 1 {
		t.Fatalf("user pivot: %+v", pv)
	}
	getJSON(t, h(ana, s.handlePivot), "/api/ui/pivot?kind=hash&value="+strings.Repeat("AB", 32), ana, &pv)
	if pv.Total != 1 {
		t.Fatalf("hash pivot: %+v", pv)
	}
	if c := getJSON(t, h(ana, s.handlePivot), "/api/ui/pivot?kind=ip&value=../../etc", ana, &pv); c != 400 {
		t.Fatalf("bad value: %d", c)
	}

	var recs []viewRecord
	getJSON(t, h(ana, s.handleRecords), "/api/ui/records?seq="+itoa(login.Seq), ana, &recs)
	if len(recs) != 1 || recs[0].Event.Type != "ssh.login" || len(recs[0].Entities) != 2 {
		t.Fatalf("records: %+v", recs)
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

func TestSnapshotRequests(t *testing.T) {
	s := forensicServer(t)
	a := s.state.Agents["a1"]
	fresh := []*Alert{
		{ID: "x1", Agent: "a1", Rule: "process.reverse_shell", Severity: "critical", Detail: "pid=4242\n"},
		{ID: "x2", Agent: "a1", Rule: "process.miner", Severity: "critical"},
		{ID: "x3", Agent: "a2", Rule: "process.miner", Severity: "critical"},
		{ID: "x4", Agent: "a1", Rule: "secret.exposed", Severity: "high"},
	}
	s.autoSnapshots(fresh)
	if len(s.state.Snapshots) != 1 || s.state.Snapshots[0].PID != 4242 || s.state.Snapshots[0].Alert != "x1" {
		t.Fatalf("one automatic request per host and window, only for activity, only where enabled: %+v", s.state.Snapshots)
	}
	reqs := s.pendingSnapshots("a1")
	if len(reqs) != 1 {
		t.Fatal("request not in the agent config")
	}
	rec := appendAt(t, s, "a1", time.Now(), "forensics.snapshot", map[string]any{"request": reqs[0].ID, "alert": "x1", "trigger": "request", "pid": 4242.0,
		"target": map[string]any{"comm": "bash", "exe": "/usr/bin/bash", "exe_sha256": strings.Repeat("cd", 32)}, "sha256": "f00"})
	s.evaluate(a, rec)
	if s.state.Snapshots[0].Status != "done" || s.state.Snapshots[0].Seq != rec.Seq || len(a.SnapshotIndex) != 1 || a.SnapshotIndex[0].Comm != "bash" {
		t.Fatalf("received: %+v %+v", s.state.Snapshots[0], a.SnapshotIndex)
	}
	if len(s.pendingSnapshots("a1")) != 0 {
		t.Fatal("done requests are not sent again")
	}
	// The agent's own snapshot suppresses an automatic request.
	a.LastSnapshotAsk = time.Time{}
	s.autoSnapshots([]*Alert{{ID: "x5", Agent: "a1", Rule: "process.miner", Severity: "critical"}})
	if len(s.state.Snapshots) != 1 {
		t.Fatal("asked again right after a snapshot")
	}
	if es := entities(rec.Event); len(es) != 1 || es[0].Kind != "hash" {
		t.Fatalf("snapshot hash is pivotable: %+v", es)
	}
}

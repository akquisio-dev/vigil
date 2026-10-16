package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

type testAgent struct {
	s   *Server
	a   *AgentRec
	key ed25519.PrivateKey
	seq int64
}

func newTestAgent(t *testing.T, s *Server) *testAgent {
	pub, priv, _ := ed25519.GenerateKey(nil)
	a := &AgentRec{ID: "a1", Name: "web", PublicKey: proto.EncodeKey(pub), Baseline: map[string]bool{}, SelfTest: true, StartedOnce: true}
	s.mu.Lock()
	s.state.Agents[a.ID] = a
	s.mu.Unlock()
	return &testAgent{s: s, a: a, key: priv}
}

func (ta *testAgent) send(t *testing.T, evs ...proto.Event) proto.BatchResponse {
	ta.seq++
	body, _ := json.Marshal(proto.Batch{AgentID: ta.a.ID, Seq: ta.seq, SentAt: time.Now(), Events: evs})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/events", bytes.NewReader(body))
	req.Header.Set(proto.SigHeader, proto.Sign(ta.key, body))
	w := httptest.NewRecorder()
	ta.s.handleEvents(w, req)
	if w.Code != 200 {
		t.Fatalf("batch refused: %d %s", w.Code, w.Body)
	}
	var br proto.BatchResponse
	json.Unmarshal(w.Body.Bytes(), &br)
	return br
}

func (s *Server) openAlerts(rule string) []*Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Alert
	for _, al := range s.state.Alerts {
		if al.Rule == rule && al.Status == "open" {
			out = append(out, al)
		}
	}
	return out
}

func TestSelfTestEndToEnd(t *testing.T) {
	k := &sink{}
	hook := httptest.NewServer(http.HandlerFunc(k.handler))
	defer hook.Close()
	s, err := New(&Config{DataDir: t.TempDir(), Notifiers: []NotifierConfig{{Type: "webhook", Name: "hook", MinSeverity: "critical", URL: hook.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	ta := newTestAgent(t, s)

	s.mu.Lock()
	st, err := s.startSelfTest(ta.a, "admin")
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, err = s.startSelfTest(ta.a, "admin")
	s.mu.Unlock()
	if err == nil {
		t.Fatal("two tests at once on one host")
	}

	// The test id reaches the agent in the signed configuration.
	br := ta.send(t)
	var cfg proto.AgentConfig
	json.Unmarshal(br.Config, &cfg)
	if cfg.SelfTest == nil || cfg.SelfTest.ID != st.ID {
		t.Fatalf("self test not in config: %s", br.Config)
	}

	marker := "vigil-selftest-" + st.ID
	ta.send(t,
		proto.NewEvent("selftest.started", map[string]any{"id": st.ID}),
		proto.NewEvent("file.added", map[string]any{"path": "/etc/cron.d/" + marker, "category": "cron", "hash": "x"}),
		proto.NewEvent("file.removed", map[string]any{"path": "/etc/cron.d/" + marker, "category": "cron"}),
		// A real attack during the test must still alert.
		proto.NewEvent("file.added", map[string]any{"path": "/etc/cron.d/evil", "category": "cron", "hash": "y"}),
		proto.NewEvent("process.exec", map[string]any{"exe": "/tmp/" + marker + "-1/sleep", "comm": "sleep", "uid": 0, "signals": []any{"tmp_exe"}}),
		proto.NewEvent("selftest.done", map[string]any{"id": st.ID}),
	)
	if n := len(s.openAlerts("file.cron")); n != 1 {
		t.Fatalf("want exactly the real file.cron alert, got %d", n)
	}
	if len(s.openAlerts("process.tmp_exec")) != 0 {
		t.Fatal("test trace raised an alert")
	}
	s.mu.Lock()
	s.checkSelfTests()
	open := st.open()
	s.mu.Unlock()
	if !open {
		t.Fatal("finished while the journal step is still due")
	}

	ta.send(t, proto.NewEvent("log.spoofed", map[string]any{"identifier": "sshd", "comm": "vigil-agent", "uid": "0", "message": marker + " (vigil self test)"}))
	s.mu.Lock()
	s.checkSelfTests()
	status := st.Status
	s.mu.Unlock()
	if status != "passed" {
		t.Fatalf("status %s, steps %+v", status, st.Steps)
	}
	if len(s.openAlerts("log.spoofed")) != 0 {
		t.Fatal("journal trace raised an alert")
	}

	// The result reaches every notifier, even one set to critical only.
	deadline := time.Now().Add(3 * time.Second)
	for k.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if k.count() != 1 || !strings.Contains(k.bodies[0]["text"].(string), "passed") {
		t.Fatalf("summary not delivered: %v", k.bodies)
	}
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := st.Notified["hook"]
		s.mu.Unlock()
		if got == "ok" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Notified["hook"] != "ok" {
		t.Fatalf("delivery not recorded: %v", st.Notified)
	}

	// The marker of a finished test no longer hides anything.
	ta.send(t, proto.NewEvent("process.exec", map[string]any{"exe": "/tmp/" + marker + "-2/sleep", "comm": "sleep", "uid": 0, "signals": []any{"tmp_exe"}}))
	if len(s.openAlerts("process.tmp_exec")) != 1 {
		t.Fatal("finished test still swallows findings")
	}
}

func TestSelfTestMissingStepFails(t *testing.T) {
	s, err := New(&Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ta := newTestAgent(t, s)
	s.mu.Lock()
	st, _ := s.startSelfTest(ta.a, "admin")
	s.mu.Unlock()
	marker := "vigil-selftest-" + st.ID
	ta.send(t,
		proto.NewEvent("selftest.started", map[string]any{"id": st.ID}),
		proto.NewEvent("file.added", map[string]any{"path": "/etc/cron.d/" + marker, "category": "cron", "hash": "x"}),
		proto.NewEvent("selftest.step", map[string]any{"id": st.ID, "step": "journal", "skipped": "ssh collector is off"}),
		proto.NewEvent("selftest.done", map[string]any{"id": st.ID}),
	)
	s.mu.Lock()
	st.Ran = time.Now().Add(-selfTestGrace - time.Second)
	s.checkSelfTests()
	s.mu.Unlock()
	if st.Status != "failed" || st.step("process").Status != "missing" || st.step("journal").Status != "skipped" {
		t.Fatalf("got %s %+v", st.Status, st.Steps)
	}
	al := s.openAlerts("selftest.failed")
	if len(al) != 1 || !strings.Contains(al[0].Title, "process") {
		t.Fatalf("selftest.failed not raised: %+v", al)
	}
	if Suppressible("selftest.failed") {
		t.Fatal("selftest.failed must not be suppressible")
	}
}

func TestSelfTestScheduleAndAgentWithoutSupport(t *testing.T) {
	s, err := New(&Config{DataDir: t.TempDir(), SelfTestDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	ta := newTestAgent(t, s)
	old := &AgentRec{ID: "a2", Name: "old"}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Agents[old.ID] = old
	if !s.scheduleSelfTests() || len(s.state.SelfTests) != 1 || s.state.SelfTests[0].Agent != ta.a.ID {
		t.Fatalf("schedule: %+v", s.state.SelfTests)
	}
	if s.scheduleSelfTests() {
		t.Fatal("scheduled twice within the period")
	}
	if _, err := s.startSelfTest(old, "admin"); err == nil {
		t.Fatal("agent without self test support accepted a test")
	}
	// Never picked up: fails after the wait.
	s.state.SelfTests[0].Created = time.Now().Add(-selfTestWait - selfTestGrace - time.Second)
	s.checkSelfTests()
	if st := s.state.SelfTests[0]; st.Status != "failed" || st.Error == "" {
		t.Fatalf("unclaimed test: %+v", st)
	}
}

package server

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// A write that fails must not move the head: the next record chains to the
// last one on disk and the chain stays whole.
func TestAppendFailureKeepsChain(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	ev := func() *Record { return &Record{Source: "agent", Event: proto.NewEvent("test.event", nil)} }
	if err := st.Append(ev()); err != nil {
		t.Fatal(err)
	}
	seq, head := st.Head()
	good := st.file
	ro, err := os.Open(filepath.Join(dir, st.day+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	st.file = ro // writes fail, as on a full disk
	if err := st.Append(ev(), ev()); err == nil {
		t.Fatal("the write should have failed")
	}
	if s2, h2 := st.Head(); s2 != seq || h2 != head {
		t.Fatalf("head moved by a failed write: seq %d -> %d", seq, s2)
	}
	if ok, _ := st.Health(); ok {
		t.Fatal("a failed write is unhealthy")
	}
	ro.Close()
	st.file = good
	if err := st.Append(ev()); err != nil {
		t.Fatal(err)
	}
	if ok, msg := st.Verify(); !ok {
		t.Fatalf("chain broken after a failed write: %s", msg)
	}
	if s3, _ := st.Head(); s3 != seq+1 {
		t.Fatalf("seq %d, want %d", s3, seq+1)
	}
}

// A blocked address leaves one record per window, not one per request.
func TestLoginFloodIsNotLogged(t *testing.T) {
	s, err := New(&Config{DataDir: t.TempDir(), SessionHours: 1, RecentEvents: 100})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		r := httptest.NewRequest("POST", "/api/ui/login", strings.NewReader(`{"user":"nobody","password":"x","code":"000000"}`))
		w := httptest.NewRecorder()
		s.handleLogin(w, r)
		want := 401
		if i >= limitFails {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("request %d: status %d, want %d", i, w.Code, want)
		}
	}
	n := 0
	s.store.Each(func(rec Record) {
		if rec.Event.Type == "admin.login_failed" {
			n++
		}
	})
	if n != limitFails+1 {
		t.Fatalf("%d login_failed records for 40 requests, want %d", n, limitFails+1)
	}
}

func TestTrimAlertsKeepsOpen(t *testing.T) {
	var alerts []*Alert
	for i := 0; i < 10; i++ {
		st := "resolved"
		if i < 3 {
			st = "open" // the oldest three are still open
		}
		alerts = append(alerts, &Alert{ID: string(rune('a' + i)), Status: st})
	}
	got := trimAlerts(alerts, 6)
	if len(got) != 6 {
		t.Fatalf("%d alerts, want 6", len(got))
	}
	for i := 0; i < 3; i++ {
		if got[i].Status != "open" || got[i].ID != alerts[i].ID {
			t.Fatalf("open alert %d was dropped: %+v", i, got[i])
		}
	}
	if got[5].ID != "j" {
		t.Fatal("the newest alert stays")
	}
	// only open ones left: the oldest go
	all := []*Alert{{ID: "1", Status: "open"}, {ID: "2", Status: "open"}, {ID: "3", Status: "open"}}
	if got := trimAlerts(all, 2); len(got) != 2 || got[0].ID != "2" {
		t.Fatalf("open only: %+v", got)
	}
}

func TestUnknownRoleIsWeakest(t *testing.T) {
	for role, want := range map[string]string{"": "admin", "admin": "admin", "analyst": "analyst", "viewer": "viewer", "Admin": "viewer", "root": "viewer"} {
		if got := roleOf(&User{Role: role}); got != want {
			t.Errorf("role %q counts as %q, want %q", role, got, want)
		}
	}
}

func TestLimiterSweepAndSessions(t *testing.T) {
	l := &limiter{fails: map[string][]time.Time{"old": {time.Now().Add(-2 * limitWindow)}, "new": {time.Now()}}}
	l.sweep()
	if _, ok := l.fails["old"]; ok || len(l.fails) != 1 {
		t.Fatalf("sweep left %v", l.fails)
	}
	s := &Server{sessions: map[string]*session{"a": {Expires: time.Now().Add(-time.Minute)}, "b": {Expires: time.Now().Add(time.Minute)}}}
	s.expireSessions()
	if len(s.sessions) != 1 || s.sessions["b"] == nil {
		t.Fatalf("sessions left: %v", s.sessions)
	}
}

func TestAgentIPIgnoresProxyHeaderOnOwnListener(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/agent/events", nil)
	r.RemoteAddr = "10.0.0.5:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	shared := &Server{cfg: &Config{TrustProxy: true}}
	if ip := shared.agentIP(r); ip != "203.0.113.1" {
		t.Fatalf("shared listener behind the proxy: %s", ip)
	}
	own := &Server{cfg: &Config{TrustProxy: true, AgentListen: "10.0.0.1:8471"}}
	if ip := own.agentIP(r); ip != "10.0.0.5" {
		t.Fatalf("own listener: %s", ip)
	}
}

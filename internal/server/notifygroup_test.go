package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIncidentAlertsAreGrouped(t *testing.T) {
	k := &sink{}
	srv := httptest.NewServer(http.HandlerFunc(k.handler))
	defer srv.Close()
	cfg := &Config{DataDir: t.TempDir(), PublicURL: "https://soc.example", Notifiers: []NotifierConfig{
		{Type: "webhook", Name: "hook", MinSeverity: "medium", URL: srv.URL},
	}}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.groupDelay = 300 * time.Millisecond
	s.state.Agents["a1"] = &AgentRec{ID: "a1", Name: "web"}

	alert := func(id, rule, sev string) *Alert {
		al := &Alert{ID: id, Rule: rule, Severity: sev, Agent: "a1", Created: time.Now(), Status: "open"}
		s.state.Alerts = append(s.state.Alerts, al)
		return al
	}
	wait := func(n int) {
		deadline := time.Now().Add(3 * time.Second)
		for k.count() < n && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		if k.count() != n {
			t.Fatalf("got %d messages, want %d: %v", k.count(), n, k.bodies)
		}
	}

	s.mu.Lock()
	first := alert("1", "ssh.password_login", "high")
	s.correlate([]*Alert{first})
	s.notifyAlerts([]*Alert{first})
	s.mu.Unlock()
	wait(1) // the first alert of the incident goes out at once

	s.mu.Lock()
	var more []*Alert
	for i, r := range []string{"file.cron", "file.cron", "user.added", "port.new"} {
		more = append(more, alert(string(rune('a'+i)), r, "high"))
	}
	more = append(more, alert("m", "port.new", "medium"))
	s.correlate(more)
	s.notifyAlerts(more)
	s.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	if k.count() != 1 {
		t.Fatalf("follow-up alerts were sent at once: %d messages", k.count())
	}
	wait(2) // one update for all five
	up := k.bodies[1]
	if up["severity"] != "high" || !strings.Contains(up["title"].(string), "5 more alerts") ||
		!strings.Contains(up["title"].(string), "(2x)") || up["link"] != "https://soc.example/#/incidents/"+first.Incident {
		t.Fatalf("update: %v", up)
	}

	// More severe than anything sent: at once, and it takes the waiting ones along.
	s.mu.Lock()
	low := alert("x", "port.new", "high")
	crit := alert("y", "proc.reverse_shell", "critical")
	s.correlate([]*Alert{low, crit})
	s.notifyAlerts([]*Alert{low, crit})
	s.mu.Unlock()
	wait(3)
	if k.bodies[2]["severity"] != "critical" || !strings.Contains(k.bodies[2]["title"].(string), "+1 more") {
		t.Fatalf("escalation: %v", k.bodies[2])
	}
	time.Sleep(500 * time.Millisecond)
	if k.count() != 3 {
		t.Fatalf("the taken-along alert was sent again: %v", k.bodies[3:])
	}

	// Alerts outside incidents, and grouping turned off, are sent one by one.
	s.mu.Lock()
	lone := alert("z", "port.new", "medium")
	s.notifyAlerts([]*Alert{lone})
	s.mu.Unlock()
	wait(4)
	s.groupDelay = 0
	cfg.NotifyGroupMinutes = -1
	s.mu.Lock()
	again := alert("w", "file.cron", "high")
	s.correlate([]*Alert{again})
	s.notifyAlerts([]*Alert{again})
	s.mu.Unlock()
	wait(5)
}

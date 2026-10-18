package server

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestSummary(t *testing.T) {
	off := false
	cfg := &Config{DataDir: t.TempDir(), Language: "de", SummaryTime: "07:30", PublicURL: "https://soc.example",
		Notifiers: []NotifierConfig{{Type: "webhook", Name: "a", URL: "http://127.0.0.1:1/x"}, {Type: "webhook", Name: "b", URL: "http://127.0.0.1:1/y", Summary: &off}}}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	loc := time.Local
	day := func(h, m int) time.Time { return time.Date(2026, 10, 18, h, m, 0, 0, loc) }

	if s.summaryDue(day(7, 29)) {
		t.Error("due before its time")
	}
	if !s.summaryDue(day(7, 30)) || !s.summaryDue(day(23, 0)) {
		t.Error("not due after its time")
	}
	s.state.LastSummary = day(7, 31)
	if s.summaryDue(day(23, 0)) {
		t.Error("due twice on one day")
	}
	if !s.summaryDue(day(7, 30).Add(24 * time.Hour)) {
		t.Error("not due the next day")
	}

	now := day(8, 0)
	s.state.Agents["a1"] = &AgentRec{ID: "a1", Name: "web"}
	s.state.Agents["a2"] = &AgentRec{ID: "a2", Name: "game", Silent: true, LastSeen: day(6, 5)}
	for i, sev := range []string{"critical", "high", "high", "medium", "low"} {
		s.state.Alerts = append(s.state.Alerts, &Alert{ID: string(rune('a' + i)), Rule: "file.cron", Severity: sev, Agent: "a1", Created: now.Add(-time.Hour), Status: "open"})
	}
	s.state.Alerts = append(s.state.Alerts, &Alert{ID: "old", Rule: "user.added", Severity: "critical", Created: now.Add(-48 * time.Hour), Status: "resolved"})
	s.state.Incidents = append(s.state.Incidents, &Incident{ID: "i1", Status: "open"}, &Incident{ID: "i2", Status: "closed"})
	s.state.SelfTests = append(s.state.SelfTests, &SelfTest{Agent: "a2", Status: "failed", Finished: now.Add(-time.Hour)})

	txt := s.summaryText(now)
	for _, want := range []string{
		"vigil Tagesbericht 18.10.2026",
		"Alarme (24 h): 1 kritisch, 2 hoch, 1 mittel, 1 niedrig",
		"Am häufigsten: file.cron (4)",
		"Offen: 5 Alarme, 1 Vorfall",
		"Hosts: 1 von 2 melden sich; nicht erreichbar: game (still seit 18.10. 06:05)",
		"Selbsttest fehlgeschlagen auf: game",
		"https://soc.example/",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "—") || strings.Contains(txt, " – ") {
		t.Error("dash in the summary")
	}
	if groupDigits(1234567, true) != "1.234.567" || groupDigits(999, false) != "999" || groupDigits(12345, false) != "12,345" {
		t.Error("groupDigits")
	}

	p := t.TempDir() + "/server.json"
	if err := os.WriteFile(p, []byte(`{"summary_time":"7 Uhr"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil {
		t.Error("bad summary_time accepted")
	}
}

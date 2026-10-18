package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestAgentUpdateRestartIsQuietOnlyWhenAskedAndRight(t *testing.T) {
	s, err := New(&Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	a := &AgentRec{ID: "a1", Name: "host", Version: "v0.18.0", StartedOnce: true}
	s.state.Agents[a.ID] = a
	ev := func(typ string, d map[string]any) []string {
		var rules []string
		for _, f := range s.evaluate(a, &Record{Event: proto.Event{Type: typ, TS: time.Now(), Data: d}}) {
			rules = append(rules, f.Rule)
		}
		return rules
	}

	// The agent announcing an update by itself lowers nothing.
	if got := ev("agent.stopping", nil); len(got) != 1 || got[0] != "agent.stopped" {
		t.Fatalf("unasked stop: %v", got)
	}
	if got := ev("agent.started", map[string]any{"version": "v0.19.0"}); len(got) != 1 || got[0] != "agent.restarted" {
		t.Fatalf("unasked restart: %v", got)
	}
	a.Version = "v0.18.0"

	if s.askUpdate(a, "v0.17.0", "admin") == nil || s.askUpdate(a, "latest", "admin") == nil {
		t.Fatal("downgrade or non-version accepted")
	}
	before := a.ConfigVersion
	if err := s.askUpdate(a, "v0.19.0", "admin"); err != nil {
		t.Fatal(err)
	}
	if a.ConfigVersion == before {
		t.Fatal("the request does not reach the agent")
	}
	raw, _ := s.agentConfig(a)
	var cfg proto.AgentConfig
	json.Unmarshal(raw, &cfg)
	if cfg.Update == nil || cfg.Update.Version != "v0.19.0" || cfg.Update.ID != a.Update.ID {
		t.Fatalf("config: %+v", cfg.Update)
	}
	if s.askUpdate(a, "v0.20.0", "admin") == nil {
		t.Fatal("second update while one runs")
	}

	ev("agent.update", map[string]any{"id": "other", "status": "staged"})
	if a.Update.Status != "asked" {
		t.Fatal("report with a foreign id was taken")
	}
	ev("agent.update", map[string]any{"id": a.Update.ID, "status": "staged"})
	var cfg2 proto.AgentConfig
	if raw, _ := s.agentConfig(a); json.Unmarshal(raw, &cfg2) == nil && cfg2.Update != nil {
		t.Fatal("staged update is asked again")
	}
	if got := ev("agent.stopping", nil); len(got) != 0 {
		t.Fatalf("update stop alerted: %v", got)
	}
	if got := ev("agent.started", map[string]any{"version": "v0.19.0"}); len(got) != 0 {
		t.Fatalf("update restart alerted: %v", got)
	}
	if a.Update.Status != "done" || a.Version != "v0.19.0" {
		t.Fatalf("update %+v, version %s", a.Update, a.Version)
	}
	// Done is done: the next restart alerts again.
	if got := ev("agent.started", map[string]any{"version": "v0.19.0"}); len(got) != 1 {
		t.Fatalf("restart after the update: %v", got)
	}

	// Coming back with another version (rolled back) alerts.
	s.askUpdate(a, "v0.20.0", "admin")
	ev("agent.update", map[string]any{"id": a.Update.ID, "status": "staged"})
	ev("agent.stopping", nil)
	if got := ev("agent.started", map[string]any{"version": "v0.19.0"}); len(got) != 1 || got[0] != "agent.restarted" {
		t.Fatalf("wrong version came back: %v", got)
	}
	s.mu.Lock()
	if late := s.checkUpdates(time.Now().Add(updateGap + time.Minute)); len(late) != 0 {
		t.Fatalf("stop reported again after the agent came back: %+v", late)
	}
	s.mu.Unlock()
	if got := ev("agent.update", map[string]any{"id": a.Update.ID, "status": "rolled_back", "error": "did not stay up"}); len(got) != 1 || got[0] != "agent.update_failed" {
		t.Fatalf("rollback: %v", got)
	}

	// A held stop that never comes back is reported late.
	a.Version = "v0.20.0"
	s.askUpdate(a, "v0.21.0", "admin")
	ev("agent.update", map[string]any{"id": a.Update.ID, "status": "staged"})
	ev("agent.stopping", nil)
	s.mu.Lock()
	got := s.checkUpdates(time.Now().Add(updateGap + time.Minute))
	s.mu.Unlock()
	if len(got) != 2 || got[0].Rule != "agent.stopped" || got[1].Rule != "agent.update_failed" || a.Update.Status != "failed" {
		t.Fatalf("held stop: %+v %+v", got, a.Update)
	}

	// Staged but never installed.
	a.Version = "v0.21.0"
	s.askUpdate(a, "v0.22.0", "admin")
	ev("agent.update", map[string]any{"id": a.Update.ID, "status": "staged"})
	s.mu.Lock()
	got = s.checkUpdates(time.Now().Add(updateTimeout))
	s.mu.Unlock()
	if len(got) != 1 || a.Update.Status != "failed" || a.Update.Error == "" {
		t.Fatalf("timeout: %+v %+v", got, a.Update)
	}
}

package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestReadableCanaryNeedsSupport(t *testing.T) {
	s := forensicServer(t)
	s.state.Canaries = map[string]*CanaryRec{}
	a := s.state.Agents["a1"]
	a.CanaryRoots = []string{"/opt"}
	create := func() int {
		body, _ := json.Marshal(map[string]any{"agent_id": "a1", "type": "env", "path": "/opt/app/.env.bak", "readable": true})
		w := httptest.NewRecorder()
		s.handleCanaryCreate(w, httptest.NewRequest("POST", "/api/ui/canaries", bytes.NewReader(body)), &session{User: "ana"})
		return w.Code
	}
	// An older agent would drop the field and place a 0600 file.
	if code := create(); code != 400 || len(s.state.Canaries) != 0 {
		t.Fatalf("old agent: %d, %d canaries", code, len(s.state.Canaries))
	}
	rec := &Record{Event: proto.Event{Type: "agent.started", TS: time.Now(), Data: map[string]any{"canary_roots": []any{"/opt"}, "canary_readable": true}}}
	s.evaluate(a, rec)
	if !a.CanaryReadable {
		t.Fatal("support not taken from agent.started")
	}
	if code := create(); code != 200 {
		t.Fatalf("new agent: %d", code)
	}
	for _, c := range s.state.Canaries {
		if !c.Readable {
			t.Fatal("readable not stored")
		}
	}
}

func TestCanaryAlertWithoutUid(t *testing.T) {
	s := forensicServer(t)
	s.state.Canaries = map[string]*CanaryRec{}
	fs := evalOne(s, "canary.opened", map[string]any{"path": "/root/x.txt", "comm": "head", "pid": 7.0})
	if len(fs) != 1 || fs[0].Params["uid"] != "unknown" {
		t.Fatalf("findings: %+v", fs)
	}
}

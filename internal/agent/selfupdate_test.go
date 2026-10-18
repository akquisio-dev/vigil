package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestSelfUpdateRefuses(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "v0.18.0"
	dir := t.TempDir()
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: dir}, flushNow: make(chan struct{}, 1), state: &State{}}
	last := func() map[string]any {
		t.Helper()
		if len(a.queue) == 0 {
			t.Fatal("no event")
		}
		ev := a.queue[len(a.queue)-1]
		if ev.Type != "agent.update" {
			t.Fatalf("event %s", ev.Type)
		}
		return ev.Data
	}

	a.selfUpdate(&proto.UpdateRequest{ID: "1", Version: "v0.19.0"})
	if d := last(); d["status"] != "refused" || d["error"] != "self_update is off in agent.json" {
		t.Fatalf("off: %v", d)
	}
	a.cfg.SelfUpdate = true
	for i, v := range []string{"v0.18.0", "v0.17.5", "latest", "v0.19.0; rm -rf /"} {
		a.selfUpdate(&proto.UpdateRequest{ID: string(rune('a' + i)), Version: v})
		if d := last(); d["status"] != "refused" {
			t.Fatalf("%s: %v", v, d)
		}
	}
	// One request id is handled once, even when the server sends it again.
	n := len(a.queue)
	a.selfUpdate(&proto.UpdateRequest{ID: "a", Version: "v0.18.0"})
	if len(a.queue) != n {
		t.Fatal("request handled twice")
	}

	// Nothing staged: the installer does nothing.
	if err := ApplyUpdate(a.cfg, "none.service"); err != nil {
		t.Fatal(err)
	}
	// A staged file that does not verify is refused and cleared, and the
	// result says so.
	ud := updateDir(dir)
	os.MkdirAll(ud, 0o700)
	for name, body := range map[string]string{"ready": "v0.19.0", "version": "v0.19.0", "SHA256SUMS": "x", "SHA256SUMS.sigstore.json": "{}", "binary": "#!/bin/sh\n", "request": "r1"} {
		os.WriteFile(filepath.Join(ud, name), []byte(body), 0o600)
	}
	if err := ApplyUpdate(a.cfg, "none.service"); err == nil {
		t.Fatal("unsigned update applied")
	}
	if _, err := os.Stat(filepath.Join(ud, "binary")); !os.IsNotExist(err) {
		t.Fatal("staged files left behind")
	}
	a.reportUpdate()
	if d := last(); d["status"] != "failed" || d["id"] != "r1" {
		t.Fatalf("result: %v", d)
	}
}

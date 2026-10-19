package server

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateEnrollToken(t *testing.T) {
	cfg := &Config{DataDir: filepath.Join(t.TempDir(), "data"), RecentEvents: 100}
	tok, _, err := CreateEnrollToken(cfg, "cli")
	if err != nil || !strings.HasPrefix(tok, "vgl_") {
		t.Fatalf("%q %v", tok, err)
	}
	st, err := LoadState(cfg.DataDir)
	if err != nil || st.Tokens[sha(tok)] == nil || st.Tokens[sha(tok)].By != "cli" {
		t.Fatalf("token not stored: %v", err)
	}
	store, err := OpenStore(filepath.Join(cfg.DataDir, "events"), 100)
	if err != nil || !store.ChainOK {
		t.Fatal(err)
	}
	recs := store.Recent(Query{})
	if len(recs) != 1 || recs[0].Event.Type != "enroll.token_created" || recs[0].Actor != "cli" {
		t.Fatalf("not in the audit chain: %+v", recs)
	}

	// A running server holds the data directory.
	unlock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, _, err := CreateEnrollToken(cfg, "cli"); err == nil || !strings.Contains(err.Error(), "running vigil-server") {
		t.Fatalf("made a token under a running server: %v", err)
	}
}

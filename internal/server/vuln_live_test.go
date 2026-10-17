package server

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestVulnLive fetches the real feeds for a release and matches the package
// list in VIGIL_LIVE_PACKAGES (the "packages" of a system.packages event):
//
//	VIGIL_LIVE_VULN=ubuntu:noble VIGIL_LIVE_PACKAGES=pkgs.json go test ./internal/server -run TestVulnLive -v
func TestVulnLive(t *testing.T) {
	rel := os.Getenv("VIGIL_LIVE_VULN")
	if rel == "" {
		t.Skip("set VIGIL_LIVE_VULN to a release such as ubuntu:noble")
	}
	s := &Server{cfg: &Config{VulnLookup: true, DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	a := &AgentRec{ID: "live", Name: "live"}
	s.state.Agents[a.ID] = a
	var list [][2]string
	if raw, err := os.ReadFile(os.Getenv("VIGIL_LIVE_PACKAGES")); err == nil {
		json.Unmarshal(raw, &list)
	}
	s.pkgs = map[string]*agentPackages{a.ID: {Eco: rel, List: list}}
	start := time.Now()
	s.refreshVulns()
	t.Logf("refresh took %s: %+v", time.Since(start).Round(time.Second), s.vulnStatus())
	if s.vdb.idx[rel] == nil {
		t.Fatal("no index")
	}
	back := s.loadIndex(rel)
	if back == nil || len(back.Recs) < len(s.vdb.idx[rel].Recs) {
		t.Fatal("index does not load back")
	}
	full, kept := 0, 0
	for _, r := range back.Recs {
		full += len(r.Pkgs)
	}
	for _, r := range s.vdb.idx[rel].Recs {
		kept += len(r.Pkgs)
	}
	t.Logf("package entries: %d on disk, %d in memory", full, kept)
	if fi, err := os.Stat(s.vulnDir() + "/" + ecoFile(rel) + ".json.gz"); err == nil {
		t.Logf("index file %d bytes", fi.Size())
	}
	// A second refresh right away must not download again.
	s.vdb.idx[rel].Updated = time.Time{}
	start = time.Now()
	s.refreshVulns()
	t.Logf("second refresh took %s", time.Since(start).Round(time.Millisecond))
	b, _ := json.MarshalIndent(a.Vulns, "", " ")
	t.Logf("summary: %s", b)
	for _, al := range s.state.Alerts {
		t.Logf("alert: %s %s", al.Severity, al.Title)
	}
}

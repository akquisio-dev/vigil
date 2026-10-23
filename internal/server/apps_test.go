package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

var osvRecords = map[string]string{
	"npm/GHSA-r5fr-rjxr-66jc": `{"id":"GHSA-r5fr-rjxr-66jc","modified":"2026-10-17T02:56:15Z","aliases":["CVE-2026-4800"],"summary":"lodash code injection",
"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"4.18.0"}]}]}],"database_specific":{"severity":"HIGH"}}`,
	"npm/GHSA-lowl-lowl-lowl": `{"id":"GHSA-lowl-lowl-lowl","modified":"2026-10-01T00:00:00Z","aliases":["CVE-2026-1"],
"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.22"}]}]}],"database_specific":{"severity":"LOW"}}`,
	"npm/GHSA-expr-expr-expr": `{"id":"GHSA-expr-expr-expr","modified":"2026-10-01T00:00:00Z","aliases":["CVE-2026-9999"],
"affected":[{"package":{"name":"express","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.20.0"}]}]}],"database_specific":{"severity":"MODERATE"}}`,
	"npm/MAL-2026-17907": `{"id":"MAL-2026-17907","modified":"2026-10-18T02:00:13Z","summary":"Malicious code in evil-pkg (npm)",
"affected":[{"package":{"name":"evil-pkg","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	"PyPI/PYSEC-2023-1": `{"id":"PYSEC-2023-1","modified":"2023-01-01T00:00:00Z","aliases":["CVE-2023-1111","GHSA-flsk-flsk-flsk"],
"affected":[{"package":{"name":"Flask-Cors","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.9"}]}]}]}`,
	"PyPI/GHSA-flsk-flsk-flsk": `{"id":"GHSA-flsk-flsk-flsk","modified":"2023-01-01T00:00:00Z","aliases":["CVE-2023-1111"],
"affected":[{"package":{"name":"flask-cors","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.9"}]}]}],"database_specific":{"severity":"CRITICAL"}}`,
}

// osvDumps serves all.zip per ecosystem from osvRecords, plus the files
// added to extra.
func osvDumps(t *testing.T, extra map[string]string) *httptest.Server {
	zips := map[string]*bytes.Buffer{}
	writers := map[string]*zip.Writer{}
	for k, body := range osvRecords {
		eco, id, _ := strings.Cut(k, "/")
		if zips[eco] == nil {
			zips[eco] = &bytes.Buffer{}
			writers[eco] = zip.NewWriter(zips[eco])
		}
		w, _ := writers[eco].Create(id + ".json")
		w.Write([]byte(body))
	}
	for _, w := range writers {
		w.Close()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if eco, ok := strings.CutSuffix(p, "/all.zip"); ok && zips[eco] != nil {
			w.Write(zips[eco].Bytes())
			return
		}
		if body, ok := extra[p]; ok {
			http.ServeContent(w, r, p, time.Time{}, strings.NewReader(body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	old := osvBase
	osvBase = srv.URL + "/"
	t.Cleanup(func() { osvBase = old })
	return srv
}

func TestAppVulnMatching(t *testing.T) {
	osvDumps(t, nil)
	s := &Server{cfg: &Config{VulnLookup: true, DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	os.MkdirAll(s.vulnDir(), 0o700)
	s.vdb.running.Store(true) // no refresh in the background (it would fetch KEV)
	s.vdb.kev = map[string]bool{"CVE-2026-9999": true}
	a := &AgentRec{ID: "a1", Name: "host", Baseline: map[string]bool{}, StartedOnce: true}
	s.state.Agents[a.ID] = a

	inv := func(pkgs ...[3]string) map[string]any {
		list := []any{}
		for _, p := range pkgs {
			list = append(list, []any{p[0], p[1], p[2], float64(0)})
		}
		return map[string]any{"manifests": []any{[]any{"/srv/app/package-lock.json", float64(len(pkgs))}}, "packages": list}
	}
	send := func(d map[string]any) []*Alert {
		rec := &Record{Event: proto.Event{Type: "system.apps", TS: time.Now(), Data: d}}
		return s.raise(s.evaluate(a, rec), a.ID, 1)
	}
	first := inv([3]string{"npm", "lodash", "4.17.21"}, [3]string{"npm", "express", "4.18.2"}, [3]string{"npm", "evil-pkg", "1.0.3"},
		[3]string{"PyPI", "Flask_Cors", "3.0.8"}, [3]string{"npm", "left-pad", "1.3.0"})

	// No data yet: nothing alerts, and the summary says what is missing.
	if fresh := send(first); len(fresh) != 0 || len(a.AppVulns.Missing) != 2 {
		t.Fatalf("without data: %+v %+v", fresh, a.AppVulns)
	}
	s.refreshOSV()
	s.mu.Lock()
	fresh := s.raise(s.matchApps(a, s.apps[a.ID]), a.ID, 1)
	s.mu.Unlock()
	got := map[string]string{}
	for _, al := range fresh {
		got[al.Rule+" "+al.Severity] += al.Title + "; "
	}
	if len(fresh) != 4 ||
		got["vuln.app_malicious critical"] != "Known malicious package evil-pkg 1.0.3 (npm) in /srv/app/package-lock.json; " ||
		got["vuln.app_exploited critical"] != "/srv/app/package-lock.json (npm): 1 vulnerabilities exploited in the wild (CVE-2026-9999) in express 4.18.2 (fixed in 4.20.0); " ||
		!strings.Contains(got["vuln.app_severe high"], "/srv/app/package-lock.json (npm): 1 high or critical vulnerabilities in lodash 4.17.21 (fixed in 4.18.0)") ||
		!strings.Contains(got["vuln.app_severe high"], "(PyPI): 1 high or critical vulnerabilities in flask-cors 3.0.8") {
		t.Fatalf("alerts: %v", got)
	}
	// PYSEC and GHSA records of one flaw count once, with the rating.
	v := a.AppVulns
	if v.Counts["critical"] != 2 || v.Counts["high"] != 1 || v.Counts["medium"] != 1 || v.Counts["low"] != 1 || len(v.Malicious) != 1 || len(v.Missing) != 0 {
		t.Fatalf("summary: %+v", v)
	}

	// Same again: quiet. Updated: the alerts close.
	if fresh := send(first); len(fresh) != 0 {
		t.Fatalf("repeated: %+v", fresh)
	}
	send(inv([3]string{"npm", "lodash", "4.18.0"}, [3]string{"npm", "express", "4.20.0"}, [3]string{"PyPI", "flask-cors", "3.0.9"}))
	for _, al := range s.state.Alerts {
		if al.Status != "resolved" {
			t.Fatalf("still open after the update: %s", al.Title)
		}
	}
}

func TestOSVSync(t *testing.T) {
	changed := `{"id":"GHSA-r5fr-rjxr-66jc","modified":"2026-10-19T00:00:00Z","aliases":["CVE-2026-4800"],
"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"4.18.0"}]}]}],"database_specific":{"severity":"CRITICAL"}}`
	// Newest first; padded so the head of the file is read in parts.
	csv := "2026-10-19T00:00:02Z,MAL-2026-17907\n2026-10-19T00:00:00Z,GHSA-r5fr-rjxr-66jc\n" + strings.Repeat("2026-10-17T00:00:00Z,GHSA-old-old-old\n", 20000)
	osvDumps(t, map[string]string{
		"npm/modified_id.csv":          csv,
		"npm/GHSA-r5fr-rjxr-66jc.json": changed,
		"npm/MAL-2026-17907.json":      `{"id":"MAL-2026-17907","modified":"2026-10-19T00:00:02Z","withdrawn":"2026-10-19T00:00:02Z","affected":[]}`,
	})
	s := &Server{cfg: &Config{VulnLookup: true, DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}}}
	os.MkdirAll(s.vulnDir(), 0o700)
	s.apps = map[string]*appInventory{"a1": {Manifests: []appManifest{{Path: "/x"}}, Packages: []appPackage{{"npm", "lodash", "4.17.21", 0}, {"npm", "evil-pkg", "1.0.0", 0}}}}

	meta, err := s.buildOSV("npm")
	if err != nil || meta.Lines != 4 {
		t.Fatalf("build: %+v %v", meta, err)
	}
	meta.Synced, _ = time.Parse(time.RFC3339, "2026-10-18T00:00:00Z")
	meta, err = s.syncOSV("npm", meta)
	if err != nil || meta.Synced.Format(time.RFC3339) != "2026-10-19T00:00:02Z" {
		t.Fatalf("sync: %+v %v", meta, err)
	}
	var ov struct{ Records map[string]json.RawMessage }
	raw, _ := os.ReadFile(s.osvPath("npm", "overlay.json"))
	json.Unmarshal(raw, &ov)
	if len(ov.Records) != 2 {
		t.Fatalf("overlay: %s", raw)
	}
	s.refreshOSV()
	if e := s.odb.idx["npm"]["lodash"]; len(e) != 2 || (e[0].Severity != "critical" && e[1].Severity != "critical") {
		t.Fatalf("lodash after sync: %+v", e)
	}
	if e := s.odb.idx["npm"]["evil-pkg"]; len(e) != 0 {
		t.Fatalf("withdrawn record still there: %+v", e)
	}
	// Nothing new: the next sync changes nothing.
	if m2, err := s.syncOSV("npm", meta); err != nil || !m2.Synced.Equal(meta.Synced) || !m2.Checked.After(meta.Checked) {
		t.Fatalf("second sync: %+v %v", m2, err)
	}
}

// The dump is a snapshot: a record changed after it but before the build
// must come with the first sync.
func TestOSVSyncAfterBuild(t *testing.T) {
	changed := strings.Replace(osvRecords["npm/GHSA-r5fr-rjxr-66jc"], `"HIGH"`, `"CRITICAL"`, 1)
	modified := time.Now().UTC().Add(-3 * time.Hour).Format(time.RFC3339)
	osvDumps(t, map[string]string{
		"npm/modified_id.csv":          modified + ",GHSA-r5fr-rjxr-66jc\n2026-10-18T02:00:13Z,MAL-2026-17907\n",
		"npm/GHSA-r5fr-rjxr-66jc.json": changed,
		"npm/MAL-2026-17907.json":      osvRecords["npm/MAL-2026-17907"], // within the hour to spare
	})
	s := &Server{cfg: &Config{VulnLookup: true, DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}}}
	os.MkdirAll(s.vulnDir(), 0o700)
	meta, err := s.buildOSV("npm")
	if err != nil {
		t.Fatal(err)
	}
	if want := "2026-10-18T01:00:13Z"; meta.Synced.Format(time.RFC3339) != want {
		t.Fatalf("watermark %v, want %s (newest record of the dump, an hour to spare)", meta.Synced, want)
	}
	if _, err := s.syncOSV("npm", meta); err != nil {
		t.Fatal(err)
	}
	if ov := s.loadOverlay("npm"); ov.Records["GHSA-r5fr-rjxr-66jc"]["lodash"] == nil || ov.Records["GHSA-r5fr-rjxr-66jc"]["lodash"].Severity != "critical" {
		t.Fatalf("change after the snapshot missed: %+v", ov.Records)
	}
}

// Without data for one ecosystem (a failed download), its open alerts stay
// open and the other ecosystems still alert.
func TestAppVulnMissingEcosystem(t *testing.T) {
	osvDumps(t, nil)
	s := &Server{cfg: &Config{VulnLookup: true, DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	os.MkdirAll(s.vulnDir(), 0o700)
	s.vdb.running.Store(true)
	a := &AgentRec{ID: "a1", Name: "host", Baseline: map[string]bool{}, StartedOnce: true}
	s.state.Agents[a.ID] = a
	inv := &appInventory{Manifests: []appManifest{{Path: "/srv/x"}}, Packages: []appPackage{{"npm", "evil-pkg", "1.0.0", 0}, {"PyPI", "flask-cors", "3.0.8", 0}}}
	s.apps = map[string]*appInventory{"a1": inv}
	s.refreshOSV()
	s.mu.Lock()
	defer s.mu.Unlock()
	if fresh := s.raise(s.matchApps(a, inv), a.ID, 1); len(fresh) != 2 {
		t.Fatalf("first: %d alerts", len(fresh))
	}
	delete(s.odb.idx, "npm")
	inv.Packages = append(inv.Packages, appPackage{"npm", "lodash", "4.17.21", 0})
	inv.Packages[1].Version = "3.0.9" // flask-cors updated
	s.raise(s.matchApps(a, inv), a.ID, 1)
	open := map[string]bool{}
	for _, al := range s.state.Alerts {
		open[al.Rule+" "+al.Status] = true
	}
	if !open["vuln.app_malicious open"] || !open["vuln.app_severe resolved"] || len(a.AppVulns.Missing) != 1 {
		t.Fatalf("alerts: %v, missing %v", open, a.AppVulns.Missing)
	}
}

// Known flaws come as one alert per lock file: it is updated in one go.
func TestAppVulnsOnePerLockFile(t *testing.T) {
	osvRecords["npm/GHSA-mini-mini-mini"] = `{"id":"GHSA-mini-mini-mini","modified":"2026-10-17T02:56:15Z","aliases":["CVE-2026-5555"],"summary":"minimist prototype pollution",
"affected":[{"package":{"name":"minimist","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.8"}]}]}],"database_specific":{"severity":"CRITICAL"}}`
	t.Cleanup(func() { delete(osvRecords, "npm/GHSA-mini-mini-mini") })
	osvDumps(t, nil)
	s := &Server{cfg: &Config{VulnLookup: true, DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	os.MkdirAll(s.vulnDir(), 0o700)
	s.vdb.running.Store(true)
	a := &AgentRec{ID: "a1", Name: "host", Baseline: map[string]bool{}, StartedOnce: true}
	s.state.Agents[a.ID] = a
	inv := &appInventory{Manifests: []appManifest{{Path: "/srv/a/package-lock.json"}, {Path: "/srv/b/package-lock.json"}},
		Packages: []appPackage{{"npm", "lodash", "4.17.21", 0}, {"npm", "minimist", "1.2.5", 0}, {"npm", "lodash", "4.17.21", 1}}}
	s.apps = map[string]*appInventory{"a1": inv}
	s.refreshOSV()
	s.mu.Lock()
	defer s.mu.Unlock()
	fresh := s.raise(s.matchApps(a, inv), a.ID, 1)
	var titles []string
	for _, al := range fresh {
		titles = append(titles, al.Title)
	}
	sort.Strings(titles)
	if len(fresh) != 2 ||
		titles[0] != "/srv/a/package-lock.json (npm): 2 high or critical vulnerabilities in lodash 4.17.21 (fixed in 4.18.0), minimist 1.2.5 (fixed in 1.2.8)" &&
			titles[0] != "/srv/a/package-lock.json (npm): 2 high or critical vulnerabilities in minimist 1.2.5 (fixed in 1.2.8), lodash 4.17.21 (fixed in 4.18.0)" ||
		titles[1] != "/srv/b/package-lock.json (npm): 1 high or critical vulnerabilities in lodash 4.17.21 (fixed in 4.18.0)" {
		t.Fatalf("alerts: %q", titles)
	}
	// one package updated: the lock file's alert stays, with the other
	inv.Packages[0].Version = "4.18.0"
	if fresh := s.raise(s.matchApps(a, inv), a.ID, 1); len(fresh) != 0 {
		t.Fatalf("a smaller group is no new alert: %v", fresh)
	}
}

package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testAbuseKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"

func TestAbuseKey(t *testing.T) {
	dir := t.TempDir()
	s := &Server{cfg: &Config{DataDir: dir}}
	if _, err := s.abuseKey(); !errors.Is(err, errNoAbuseKey) {
		t.Fatalf("no key file: %v", err)
	}
	s.cfg.AbuseCHKeyFile = filepath.Join(dir, "abusech.key")
	os.WriteFile(s.cfg.AbuseCHKeyFile, []byte("not a key/../x\n"), 0o600)
	if _, err := s.abuseKey(); err == nil || strings.Contains(err.Error(), "not a key") {
		t.Fatalf("bad key must be refused without echoing it: %v", err)
	}
	os.WriteFile(s.cfg.AbuseCHKeyFile, []byte(testAbuseKey+"\n"), 0o600)
	url, key, err := s.abuseURL(tfExport)
	if err != nil || key != testAbuseKey || url != "https://threatfox-api.abuse.ch/v2/files/exports/"+testAbuseKey+"/recent.json" {
		t.Fatalf("url %q key %q err %v", url, key, err)
	}
	if publicURL(tfExport) != "https://threatfox-api.abuse.ch/v2/files/exports/<key>/recent.json" {
		t.Fatal(publicURL(tfExport))
	}
	// net/http quotes the URL in its errors; the key must not survive that
	client := &http.Client{Timeout: 2 * time.Second}
	_, derr := download(client, "http://127.0.0.1:1/v2/files/exports/"+testAbuseKey+"/recent.json")
	if derr == nil || !strings.Contains(derr.Error(), testAbuseKey) {
		t.Fatalf("expected the raw error to carry the key: %v", derr)
	}
	if msg := redactKey(derr.Error(), key); strings.Contains(msg, testAbuseKey) || !strings.Contains(msg, "<key>") {
		t.Fatalf("not redacted: %s", msg)
	}
}

func TestAbuseExportParsers(t *testing.T) {
	tf := []byte(`{"1600001":[{"ioc_value":"198.51.100.7:443","ioc_type":"ip:port","threat_type":"botnet_cc"}],
"1600002":[{"ioc_value":"[2001:db8::5]:8080","ioc_type":"ip:port"}],
"1600003":[{"ioc_value":"evil.example","ioc_type":"domain"}],
"1600004":[{"ioc_value":"` + strings.Repeat("ab", 32) + `","ioc_type":"sha256_hash"}]}`)
	ps := parseThreatFox(tf)
	if len(ps) != 2 || ps[0].Addr().String() != "198.51.100.7" && ps[1].Addr().String() != "198.51.100.7" {
		t.Fatalf("threatfox json: %v", ps)
	}
	// a copy saved before October 2026 is the older CSV export
	old := []byte(`# comment
"2026-10-20 10:00:00", "1500001", "203.0.113.9:4444", "ip:port"`)
	if ps := parseThreatFox(old); len(ps) != 1 || ps[0].Addr().String() != "203.0.113.9" {
		t.Fatalf("threatfox csv: %v", ps)
	}
	var hs []hashEntry
	if err := parseThreatFoxHashes(tf, &hs); err != nil || len(hs) != 1 {
		t.Fatalf("threatfox hashes: %v %v", hs, err)
	}

	sha := strings.Repeat("0f", 32)
	mb := `################################################################
# MalwareBazaar recent malware samples (CSV)
# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
"2026-10-23 05:55:01","` + sha + `","` + strings.Repeat("1", 32) + `","` + strings.Repeat("2", 40) + `","abuse_ch","x.exe","exe","application/x-dosexec","AgentTesla","n/a","n/a","` + strings.Repeat("3", 32) + `","3:a:b","T1` + strings.Repeat("4", 70) + `"
` + strings.ToUpper(strings.Repeat("e7", 32)) + `
` + strings.Repeat("5", 96) + `
`
	var got []hashEntry
	parseHashLines(bytes.NewReader([]byte(mb)), 1, &got)
	if len(got) != 2 {
		t.Fatalf("malwarebazaar: %d hashes, want the CSV row and the plain line, not SHA3-384 or TLSH", len(got))
	}
	if k, _ := hashKey(sha); got[0].k != k {
		t.Fatal("wrong column taken from the CSV row")
	}
}

func TestRefreshIntelWithoutKeyAsksNothing(t *testing.T) {
	dir := t.TempDir()
	s := &Server{cfg: &Config{DataDir: dir, ThreatIntel: true}}
	saved := intelLists
	intelLists = []intelList{saved[1]}
	defer func() { intelLists = saved }()
	if intelLists[0].Name != "threatfox" || !intelLists[0].Keyed {
		t.Fatal("test expects the keyed threatfox list")
	}
	s.refreshIntel()
	st := s.intel.status()
	if len(st) != 1 || !strings.Contains(st[0].Error, "abuse.ch Auth-Key") || strings.Contains(st[0].URL, "%s") {
		t.Fatalf("status: %+v", st)
	}
	// an older copy is still used, with its own date
	os.MkdirAll(filepath.Join(dir, "intel"), 0o700)
	p := filepath.Join(dir, "intel", "threatfox.txt")
	os.WriteFile(p, []byte(`"2026-10-20 10:00:00", "1", "203.0.113.9:4444", "ip:port"`), 0o600)
	then := time.Now().Add(-60 * time.Hour)
	os.Chtimes(p, then, then)
	s2 := &Server{cfg: s.cfg}
	s2.refreshIntel()
	if list, ok := s2.intel.lookup("203.0.113.9"); !ok || list != "threatfox" {
		t.Fatal("old copy not used")
	}
	if st := s2.intel.status(); st[0].Updated.Sub(then).Abs() > time.Second {
		t.Fatalf("old copy dated %v, want %v", st[0].Updated, then)
	}
}

func TestIntelStale(t *testing.T) {
	s := &Server{cfg: &Config{DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}}}
	now := time.Now().UTC()
	s.started = now.Add(-time.Hour)
	src := func(last time.Time, err string) map[string][2]string {
		return map[string][2]string{"threatfox": {last.Format(time.RFC3339), err}}
	}
	if a := s.checkIntelStale(now, src(time.Time{}, errNoAbuseKey.Error())); len(a) != 0 {
		t.Fatal("a new installation gets two days")
	}
	s.started = now.Add(-72 * time.Hour)
	a := s.checkIntelStale(now, src(now.Add(-50*time.Hour), "HTTP 410"))
	if len(a) != 1 || a[0].Rule != "intel.stale" || !strings.Contains(a[0].Title, "threatfox") || !strings.Contains(a[0].Title, "HTTP 410") {
		t.Fatalf("stale: %+v", a)
	}
	if a := s.checkIntelStale(now, src(time.Time{}, "")); len(a) != 0 {
		t.Fatal("still open: counted, not raised again")
	}
	s.checkIntelStale(now, src(now.Add(-time.Hour), ""))
	for _, al := range s.state.Alerts {
		if al.Rule == "intel.stale" && al.Status != "resolved" {
			t.Fatal("a fresh download must resolve it")
		}
	}
	// stays quiet within two days
	if a := s.checkIntelStale(now, src(now.Add(-47*time.Hour), "HTTP 500")); len(a) != 0 {
		t.Fatal("raised within two days")
	}
}

func TestAbuseDownloadsEndToEnd(t *testing.T) {
	sha := strings.Repeat("c3", 32)
	tfJSON := `{"1":[{"ioc_value":"198.51.100.77:443","ioc_type":"ip:port"}],"2":[{"ioc_value":"` + strings.Repeat("d4", 32) + `","ioc_type":"sha256_hash"}]}`
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		switch r.URL.Path {
		case "/tf/" + testAbuseKey + "/recent.json":
			w.Write([]byte(tfJSON))
		case "/mb/" + testAbuseKey + "/recent.csv":
			w.Write([]byte("# header\n\"2026-10-23 05:55:01\",\"" + sha + "\",\"x\"\n"))
		default:
			w.WriteHeader(http.StatusGone)
		}
	}))
	defer srv.Close()
	savedTF, savedMBR, savedMBF, savedLists := tfExport, mbExportRecent, mbExportFull, intelLists
	defer func() { tfExport, mbExportRecent, mbExportFull, intelLists = savedTF, savedMBR, savedMBF, savedLists }()
	tfExport, mbExportRecent, mbExportFull = srv.URL+"/tf/%s/recent.json", srv.URL+"/mb/%s/recent.csv", srv.URL+"/mb/%s/full.csv.zip"
	intelLists = []intelList{{"threatfox", tfExport, true, "critical", parseThreatFox}}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "abusech.key")
	os.WriteFile(keyFile, []byte(testAbuseKey), 0o600)
	s := &Server{cfg: &Config{DataDir: dir, ThreatIntel: true, HashIntel: true, AbuseCHKeyFile: keyFile},
		store: mustStore(t, dir), state: &State{Agents: map[string]*AgentRec{}}}
	s.refreshIntel()
	if list, ok := s.intel.lookup("198.51.100.77"); !ok || list != "threatfox" {
		t.Fatalf("threatfox address not loaded, asked %v", asked)
	}
	s.refreshHashes()
	if s.hashes.size() != 2 {
		t.Fatalf("hashes: %d, asked %v", s.hashes.size(), asked)
	}
	if s.intelOK("malwarebazaar").IsZero() {
		t.Fatal("malwarebazaar success not recorded")
	}
	// the full export failed with 410: reported, without the key
	if !strings.Contains(s.hashes.err, "malwarebazaar full") || strings.Contains(s.hashes.err, testAbuseKey) {
		t.Fatalf("hash error %q", s.hashes.err)
	}

	// a transport error quotes the URL: the key must not reach the status
	tfExport, mbExportRecent, mbExportFull = "http://127.0.0.1:1/%s/a", "http://127.0.0.1:1/%s/b", "http://127.0.0.1:1/%s/c"
	intelLists = []intelList{{"threatfox", tfExport, true, "critical", parseThreatFox}}
	os.Remove(filepath.Join(dir, "intel", "threatfox.txt"))
	s2 := &Server{cfg: s.cfg, store: s.store, state: s.state}
	s2.refreshIntel()
	s2.refreshHashes()
	st := s2.intel.status()
	all := st[0].Error + st[0].URL + s2.hashes.err + strings.Join([]string{s2.hashes.errs["malwarebazaar"], s2.hashes.errs["threatfox"]}, " ")
	if st[0].Error == "" || s2.hashes.errs["malwarebazaar"] == "" || strings.Contains(all, testAbuseKey) {
		t.Fatalf("key leaked or no error: %q", all)
	}
}

func mustStore(t *testing.T, dir string) *Store {
	t.Helper()
	st, err := OpenStore(filepath.Join(dir, "events"), 100)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

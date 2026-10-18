package osv

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompareSemver(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0}, {"1.2.3", "1.2.10", -1}, {"v1.2.3", "1.2.3", 0}, {"2.0.0", "10.0.0", -1},
		{"1.0.0-alpha", "1.0.0", -1}, {"1.0.0-alpha", "1.0.0-alpha.1", -1}, {"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1}, {"1.0.0-rc.1", "1.0.0", -1}, {"1.0.0+build", "1.0.0", 0},
		{"1.2", "1.2.0", 0},
		// Go pseudo-versions sort below the release they precede.
		{"v0.0.0-20210101000000-abcdef123456", "0.0.1", -1},
		{"v1.2.4-0.20210101000000-abcdef123456", "1.2.4", -1},
		{"v1.2.4-0.20210101000000-abcdef123456", "1.2.3", 1},
	} {
		got, ok := Compare(NPM, c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("Compare(%s, %s) = %d %v, want %d", c.a, c.b, got, ok, c.want)
		}
	}
	if _, ok := Compare(NPM, "latest", "1.0.0"); ok {
		t.Error("a tag is not a version")
	}
}

func TestComparePEP440(t *testing.T) {
	order := []string{"1.0.dev1", "1.0a1.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1.dev1", "1.0.post1", "1.0.1", "1.1", "2!0.1"}
	for i := range order {
		for j := range order {
			got, ok := Compare(PyPI, order[i], order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if !ok || got != want {
				t.Errorf("Compare(%s, %s) = %d %v, want %d", order[i], order[j], got, ok, want)
			}
		}
	}
	for _, eq := range [][2]string{{"1.0", "1.0.0"}, {"1.0RC1", "1.0rc1"}, {"1.0-1", "1.0.post1"}, {"1.0+local", "1.0"}, {"1.0alpha1", "1.0a1"}} {
		if c, ok := Compare(PyPI, eq[0], eq[1]); !ok || c != 0 {
			t.Errorf("%s != %s", eq[0], eq[1])
		}
	}
}

func TestNormalizeName(t *testing.T) {
	if got := NormalizeName(PyPI, "Flask_SQLAlchemy..x"); got != "flask-sqlalchemy-x" {
		t.Fatal(got)
	}
	if got := NormalizeName(NPM, "@Scope/Pkg"); got != "@Scope/Pkg" {
		t.Fatal(got)
	}
}

func TestCVSS3(t *testing.T) {
	for v, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10,
	} {
		got, ok := CVSS3(v)
		if !ok || got != want {
			t.Errorf("%s = %v %v, want %v", v, got, ok, want)
		}
	}
	if _, ok := CVSS3("CVSS:3.1/AV:X"); ok {
		t.Error("bad vector accepted")
	}
}

const lodash = `{"id":"GHSA-r5fr-rjxr-66jc","modified":"2026-10-17T02:56:15.633068434Z","aliases":["CVE-2026-4800"],"summary":"lodash vulnerable to Code Injection",
"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"4.18.0"}]}]}],
"database_specific":{"severity":"HIGH"}}`

const malicious = `{"id":"MAL-2026-17907","modified":"2026-10-18T02:00:13.170468730Z","aliases":["GHSA-pm76-w63j-7j29"],"summary":"Malicious code in @beloved-lenora/opencode-shell-guard (npm)",
"affected":[{"package":{"name":"@beloved-lenora/opencode-shell-guard","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`

const pysec = `{"id":"PYSEC-2023-1","modified":"2023-01-01T00:00:00Z","aliases":["CVE-2023-1111"],
"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
"affected":[{"package":{"name":"Flask_Cors","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.9"}]},{"type":"GIT","events":[{"introduced":"abc"}]}]},
{"package":{"name":"other","ecosystem":"npm"},"versions":["1.0.0"]}]}`

const goLast = `{"id":"GO-2024-0001","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2024-2222"],
"affected":[{"package":{"name":"golang.org/x/net","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.17.0"},{"introduced":"0.20.0"},{"last_affected":"0.21.0"}]}]}]}`

func entryOf(t *testing.T, raw, eco, name string) *Entry {
	t.Helper()
	_, es, withdrawn, err := Parse([]byte(raw), eco)
	if err != nil || withdrawn || es[name] == nil {
		t.Fatalf("parse %s: %v %v %v", name, err, withdrawn, es)
	}
	return es[name]
}

func TestAffects(t *testing.T) {
	l := entryOf(t, lodash, NPM, "lodash")
	if l.Severity != "high" || len(l.CVEs()) != 1 || l.Malicious() {
		t.Fatalf("%+v", l)
	}
	for v, want := range map[string]bool{"3.10.1": false, "4.0.0": true, "4.17.21": true, "4.18.0": false, "5.0.0": false, "junk": false} {
		if l.Affects(NPM, v) != want {
			t.Errorf("lodash %s: want %v", v, want)
		}
	}
	if f := l.FixedAfter(NPM, "4.17.21"); f != "4.18.0" {
		t.Errorf("fixed %q", f)
	}

	m := entryOf(t, malicious, NPM, "@beloved-lenora/opencode-shell-guard")
	if !m.Malicious() || m.Severity != "critical" || !m.Affects(NPM, "1.0.3") || !m.Affects(NPM, "not-semver") {
		t.Errorf("%+v", m)
	}

	p := entryOf(t, pysec, PyPI, "flask-cors")
	if p.Severity != "critical" || len(p.Ranges) != 1 || !p.Affects(PyPI, "3.0.8") || p.Affects(PyPI, "3.0.9") || !p.Affects(PyPI, "3.0.9rc1") {
		t.Errorf("%+v", p)
	}
	_, es, _, _ := Parse([]byte(pysec), NPM)
	if o := es["other"]; o == nil || !o.Affects(NPM, "1.0.0") || o.Affects(NPM, "1.0.1") {
		t.Errorf("versions list: %+v", o)
	}

	g := entryOf(t, goLast, Go, "golang.org/x/net")
	for v, want := range map[string]bool{"v0.16.0": true, "v0.17.0": false, "v0.19.9": false, "v0.20.0": true, "v0.21.0": true, "v0.21.1": false} {
		if g.Affects(Go, v) != want {
			t.Errorf("x/net %s: want %v", v, want)
		}
	}
	if g.Severity != "" {
		t.Errorf("Go records carry no severity, got %q", g.Severity)
	}

	if _, _, withdrawn, _ := Parse([]byte(`{"id":"GHSA-x","withdrawn":"2024-01-01T00:00:00Z","affected":[]}`), NPM); !withdrawn {
		t.Error("withdrawn not seen")
	}
}

func TestIndexAndOverlay(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "all.zip")
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	for name, body := range map[string]string{"GHSA-r5fr-rjxr-66jc.json": lodash, "MAL-2026-17907.json": malicious, "PYSEC-2023-1.json": pysec, "README": "x"} {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	f.Close()

	var idx bytes.Buffer
	raw, _ := os.ReadFile(zp)
	n, newest, err := BuildIndex(bytes.NewReader(raw), NPM, &idx)
	if err != nil || n != 3 || newest.Format(time.RFC3339) != "2026-10-18T02:00:13Z" {
		t.Fatalf("BuildIndex: %d %v %v", n, newest, err)
	}
	if _, _, err := BuildIndex(bytes.NewReader(raw[:len(raw)/2]), NPM, io.Discard); err == nil {
		t.Fatal("a cut off dump was read")
	}
	bad := bytes.Clone(raw)
	bad[60] ^= 0xff
	if _, _, err := BuildIndex(bytes.NewReader(bad), NPM, io.Discard); err == nil {
		t.Fatal("a damaged dump was read")
	}
	got, err := Scan(bytes.NewReader(idx.Bytes()), nil, map[string]bool{"lodash": true, "other": true})
	if err != nil || len(got["lodash"]) != 1 || len(got["other"]) != 1 || len(got["@beloved-lenora/opencode-shell-guard"]) != 0 {
		t.Fatalf("Scan: %v %v", got, err)
	}

	// The overlay replaces a changed record and drops a withdrawn one.
	ov := &Overlay{Records: map[string]map[string]*Entry{
		"GHSA-r5fr-rjxr-66jc": {"lodash": {ID: "GHSA-r5fr-rjxr-66jc", Severity: "critical"}},
		"PYSEC-2023-1":        {},
	}}
	got, _ = Scan(bytes.NewReader(idx.Bytes()), ov, map[string]bool{"lodash": true, "other": true})
	if len(got["lodash"]) != 1 || got["lodash"][0].Severity != "critical" || len(got["other"]) != 0 {
		t.Fatalf("overlay: %v", got)
	}
}

func TestChanged(t *testing.T) {
	csv := "2026-10-18T02:00:13.17Z,MAL-2\n2026-10-17T02:56:15Z,GHSA-a\n2026-10-16T00:00:00Z,GHSA-b\n"
	since, _ := time.Parse(time.RFC3339, "2026-10-16T12:00:00Z")
	ids, newest, complete := Changed(strings.NewReader(csv), since)
	if !complete || len(ids) != 2 || ids[0] != "MAL-2" || newest.Format(time.RFC3339Nano) != "2026-10-18T02:00:13.17Z" {
		t.Fatalf("%v %v %v", ids, newest, complete)
	}
	if _, _, complete := Changed(strings.NewReader(csv), time.Time{}); complete {
		t.Fatal("the whole file is newer than zero, more is needed")
	}
}

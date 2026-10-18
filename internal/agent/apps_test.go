package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"testing"
	"time"
)

func TestParseNpmLock(t *testing.T) {
	v3 := `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4"}},
"node_modules/express":{"version":"4.18.2","resolved":"https://r/express.tgz","dependencies":{"x":"1"}},
"node_modules/@scope/pkg":{"version":"2.0.0-beta.1"},
"node_modules/express/node_modules/debug":{"version":"2.6.9"},
"node_modules/debug":{"version":"4.3.4"},
"node_modules/alias":{"name":"lodash","version":"4.17.21"},
"node_modules/local":{"resolved":"../local","link":true},
"node_modules/gitdep":{"version":"git+ssh://git@github.com/a/b.git#abc"}}}`
	got, err := parseNpmLock(strings.NewReader(v3))
	if err != nil {
		t.Fatal(err)
	}
	want := "npm express 4.18.2|npm @scope/pkg 2.0.0-beta.1|npm debug 2.6.9|npm debug 4.3.4|npm lodash 4.17.21"
	if s := pkgString(got); s != want {
		t.Fatalf("v3:\n got %s\nwant %s", s, want)
	}

	v1 := `{"name":"old","lockfileVersion":1,"dependencies":{
"a":{"version":"1.0.0","requires":{"b":"^2"},"dependencies":{"b":{"version":"2.1.0"}}},
"b":{"version":"3.0.0","dev":true}}}`
	got, err = parseNpmLock(strings.NewReader(v1))
	if err != nil || pkgString(got) != "npm a 1.0.0|npm b 2.1.0|npm b 3.0.0" {
		t.Fatalf("v1: %s %v", pkgString(got), err)
	}
	if _, err := parseNpmLock(strings.NewReader(`[1]`)); err == nil {
		t.Fatal("an array is not a lock file")
	}
}

func TestParseRequirementsAndGoMod(t *testing.T) {
	req := "# app\nFlask==2.0.1\nrequests[socks] == 2.31.0 ; python_version > '3'\nDjango>=4\n-r other.txt\nnumpy==1.*\npkg===1.0\nurllib3==2.0.7 # pinned\ngit+https://x/y.git\n"
	if s := pkgString(parseRequirements(strings.NewReader(req))); s != "PyPI flask 2.0.1|PyPI requests 2.31.0|PyPI urllib3 2.0.7" {
		t.Fatalf("requirements: %s", s)
	}
	mod := "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/net v0.17.0\n\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n\tgithub.com/c/d v0.0.0-20210101000000-abcdef123456\n)\n\nreplace github.com/a/b => ../b\n"
	if s := pkgString(parseGoMod(strings.NewReader(mod))); s != "Go golang.org/x/net v0.17.0|Go github.com/a/b v1.2.3|Go github.com/c/d v0.0.0-20210101000000-abcdef123456" {
		t.Fatalf("go.mod: %s", s)
	}
}

func pkgString(ps []appPkg) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Eco+" "+p.Name+" "+p.Version)
	}
	return strings.Join(out, "|")
}

func TestFindManifests(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"a/package-lock.json", "a/node_modules/x/package-lock.json", "a/node_modules/.package-lock.json",
		"b/requirements.txt", "c/go.mod", "c/.git/go.mod", "d/e/f/g/h/i/j/k/l/go.mod", "e/package.json"} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte("{}"), 0o644)
	}
	os.Symlink(filepath.Join(root, "a"), filepath.Join(root, "link"))
	got, capped, err := findManifests(context.Background(), []string{root})
	if err != nil || capped {
		t.Fatal(err)
	}
	for i := range got {
		got[i] = strings.TrimPrefix(got[i], root+"/")
	}
	if s := strings.Join(got, " "); s != "a/package-lock.json b/requirements.txt c/go.mod" {
		t.Fatalf("found %s", s)
	}
}

func TestAppInventory(t *testing.T) {
	ms := []manifest{
		{Path: "/srv/a/package-lock.json", Eco: "npm", Pkgs: []appPkg{{"npm", "x", "1.0.0"}, {"npm", "y", "2.0.0"}}},
		{Path: "/srv/b/package-lock.json", Eco: "npm", Pkgs: []appPkg{{"npm", "x", "1.0.0"}, {"npm", "x", "1.1.0"}}},
	}
	d, sum := appInventory(ms)
	pk := d["packages"].([][4]any)
	if len(pk) != 3 || pk[0] != [4]any{"npm", "x", "1.0.0", 0} || pk[1] != [4]any{"npm", "x", "1.1.0", 1} || d["truncated"] != nil {
		t.Fatalf("%v", pk)
	}
	if _, sum2 := appInventory(ms[:1]); sum2 == sum {
		t.Fatal("hash ignores the change")
	}

	var big []appPkg
	for i := 0; i < 20000; i++ {
		big = append(big, appPkg{"npm", fmt.Sprintf("package-with-a-long-name-%05d", i), "1.2.3"})
	}
	d, _ = appInventory([]manifest{{Path: "/x", Eco: "npm", Pkgs: big}})
	if d["truncated"] != true || len(d["packages"].([][4]any)) >= 20000 {
		t.Fatal("not truncated")
	}
}

// A lock file of 20000 packages (about 4 MB) must not cost the agent much
// more than the file itself: it runs under MemoryHigh=64M.
func TestParseNpmLockStaysSmall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package-lock.json")
	var b strings.Builder
	b.WriteString(`{"name":"big","lockfileVersion":3,"packages":{"":{"name":"big"}`)
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&b, `,"node_modules/p%05d":{"version":"1.%d.0","resolved":"https://registry.npmjs.org/p%05d/-/p%05d-1.%d.0.tgz","integrity":"sha512-%s","dependencies":{"a":"^1","b":"^2"}}`, i, i, i, i, i, strings.Repeat("A", 88))
	}
	b.WriteString(`}}`)
	os.WriteFile(path, []byte(b.String()), 0o644)
	fi, _ := os.Stat(path)

	// Collect often, so the live heap shows what is held, and sample it
	// while the file is read.
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	base := sample[0].Value.Uint64()
	done := make(chan struct{})
	var pkgs []appPkg
	var err error
	go func() { pkgs, err = parseManifest(path); close(done) }()
	var peak uint64
	for running := true; running; {
		select {
		case <-done:
			running = false
		case <-time.After(200 * time.Microsecond):
		}
		metrics.Read(sample)
		if v := sample[0].Value.Uint64(); v > base && v-base > peak {
			peak = v - base
		}
	}
	if err != nil || len(pkgs) != appMaxPackages {
		t.Fatalf("%d packages, %v", len(pkgs), err)
	}
	// Decoding the whole file into a map takes several times its size.
	if peak > 8<<20 {
		t.Fatalf("live heap rose by %d MB for a %d MB file", peak>>20, fi.Size()>>20)
	}
	t.Logf("live heap peak +%d KB for a %d KB file", peak>>10, fi.Size()>>10)
}

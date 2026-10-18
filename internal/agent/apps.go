package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/osv"
	"github.com/akquisio-dev/vigil/internal/proto"
)

// Application dependencies for vulnerability matching on the server (OSV).
// The agent looks for lock files below a few roots: package-lock.json
// (npm), requirements.txt with pinned versions (PyPI) and go.mod (Go
// modules). Lock files are read as streams and only when they changed, and
// the list goes to the server like the dpkg list; the agent never asks a
// third party.

var appRootsDefault = []string{"/opt", "/srv", "/var/www", "/home", "/root"}

// Directories that hold installed copies, caches or test data rather than
// projects. node_modules is covered by the package-lock.json beside it.
var appSkipNames = map[string]bool{"node_modules": true, ".git": true, "vendor": true, "site-packages": true,
	"dist-packages": true, "__pycache__": true, ".cache": true, ".npm": true, ".cargo": true, ".rustup": true,
	"go": true, "testdata": true, "fixtures": true, ".pnpm-store": true, ".yarn": true, ".nvm": true, "snap": true}

const (
	appMaxDepth     = 8
	appMaxDirs      = 100000
	appMaxManifests = 300
	appMaxFile      = 32 << 20
	appMaxPackages  = 10000
	// appMaxBytes keeps the event well inside a batch (batchMaxBytes).
	appMaxBytes = 500 << 10
	appEvery    = 3 * time.Hour
)

type appPkg struct{ Eco, Name, Version string }

type manifest struct {
	Path string
	Eco  string
	Pkgs []appPkg
}

type manifestCache struct {
	size  int64
	mtime int64
	pkgs  []appPkg
}

// manifestEco names the ecosystem of a lock file by its name.
func manifestEco(name string) string {
	switch name {
	case "package-lock.json", ".package-lock.json":
		return osv.NPM
	case "requirements.txt":
		return osv.PyPI
	case "go.mod":
		return osv.Go
	}
	return ""
}

// findManifests walks the roots for lock files. It does not follow links,
// stays on the root's filesystem and stops at the limits above, saying so
// with capped.
func findManifests(ctx context.Context, roots []string) (out []string, capped bool, err error) {
	dirs := 0
	for _, root := range roots {
		var rst syscall.Stat_t
		if syscall.Stat(root, &rst) != nil {
			continue
		}
		type dir struct {
			path  string
			depth int
		}
		stack := []dir{{root, 0}}
		for len(stack) > 0 {
			d := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if dirs++; dirs > appMaxDirs || len(out) >= appMaxManifests {
				sort.Strings(out)
				return out, true, nil
			}
			if ctx.Err() != nil {
				return out, false, ctx.Err()
			}
			ents, err := os.ReadDir(d.path)
			if err != nil {
				continue
			}
			for _, e := range ents {
				p := d.path + "/" + e.Name()
				switch {
				case e.IsDir():
					var st syscall.Stat_t
					if d.depth+1 < appMaxDepth && !appSkipNames[e.Name()] && syscall.Lstat(p, &st) == nil && st.Dev == rst.Dev {
						stack = append(stack, dir{p, d.depth + 1})
					}
				case e.Type().IsRegular() && manifestEco(e.Name()) != "":
					if e.Name() == ".package-lock.json" {
						continue // npm's copy in node_modules; skipped with it
					}
					out = append(out, p)
				}
			}
			time.Sleep(100 * time.Microsecond)
		}
	}
	sort.Strings(out)
	return out, false, nil
}

// parseManifest reads one lock file.
func parseManifest(path string) ([]appPkg, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := io.LimitReader(f, appMaxFile)
	switch eco := manifestEco(baseName(path)); eco {
	case osv.NPM:
		return parseNpmLock(r)
	case osv.PyPI:
		return parseRequirements(r), nil
	case osv.Go:
		return parseGoMod(r), nil
	}
	return nil, errors.New("not a lock file")
}

func baseName(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

// parseNpmLock reads package-lock.json v1 to v3 as a token stream, one
// package at a time, so a large lock file does not become a large map.
func parseNpmLock(r io.Reader) ([]appPkg, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 32<<10))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("package-lock.json: not an object")
	}
	var out []appPkg
	seen := map[string]bool{}
	add := func(name, ver string) {
		if name == "" || ver == "" || len(out) >= appMaxPackages || strings.ContainsAny(ver, ":/") {
			return // links and git or file versions name no release
		}
		if k := name + "@" + ver; !seen[k] {
			seen[k] = true
			out = append(out, appPkg{osv.NPM, name, ver})
		}
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return out, err
		}
		key, _ := t.(string)
		switch key {
		case "packages":
			// v2 and v3: "node_modules/a/node_modules/@s/b": {"version": ...}
			if err := eachMember(dec, func(k string) error {
				var p struct {
					Version string `json:"version"`
					Name    string `json:"name"`
					Link    bool   `json:"link"`
				}
				if err := dec.Decode(&p); err != nil {
					return err
				}
				i := strings.LastIndex(k, "node_modules/")
				if i < 0 || p.Link {
					return nil // the project itself
				}
				name := k[i+len("node_modules/"):]
				if p.Name != "" && !strings.Contains(k, p.Name) {
					name = p.Name // an alias ("x": "npm:y@1")
				}
				add(name, p.Version)
				return nil
			}); err != nil {
				return out, err
			}
		case "dependencies":
			// v1: nested {"name": {"version": ..., "dependencies": {...}}}
			var walk func() error
			walk = func() error {
				return eachMember(dec, func(name string) error {
					if t, err := dec.Token(); err != nil || t != json.Delim('{') {
						return errors.New("package-lock.json: bad dependency " + name)
					}
					for dec.More() {
						t, err := dec.Token()
						if err != nil {
							return err
						}
						switch t {
						case "version":
							var v string
							if err := dec.Decode(&v); err != nil {
								return err
							}
							add(name, v)
						case "dependencies":
							if err := walk(); err != nil {
								return err
							}
						default:
							var skip json.RawMessage
							if err := dec.Decode(&skip); err != nil {
								return err
							}
						}
					}
					_, err := dec.Token()
					return err
				})
			}
			if err := walk(); err != nil {
				return out, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

// eachMember calls fn for each key of the object that comes next; fn must
// read the value.
func eachMember(dec *json.Decoder, fn func(key string) error) error {
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("expected an object")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if err := fn(t.(string)); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// parseRequirements keeps the pinned lines ("name==1.2.3", with extras or
// markers). Ranges say nothing about what is installed.
func parseRequirements(r io.Reader) []appPkg {
	var out []appPkg
	sc := bufio.NewScanner(r)
	for sc.Scan() && len(out) < appMaxPackages {
		l := sc.Text()
		if i := strings.Index(l, " #"); i >= 0 {
			l = l[:i]
		}
		if i := strings.IndexByte(l, ';'); i >= 0 {
			l = l[:i]
		}
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' || l[0] == '-' {
			continue
		}
		name, ver, ok := strings.Cut(l, "==")
		if !ok || strings.HasPrefix(ver, "=") {
			continue
		}
		if i := strings.IndexByte(name, '['); i >= 0 {
			name = name[:i]
		}
		name, ver = strings.TrimSpace(name), strings.TrimSpace(ver)
		if name == "" || ver == "" || strings.ContainsAny(ver, "*, ") || strings.ContainsAny(name, " /:@") {
			continue
		}
		out = append(out, appPkg{osv.PyPI, osv.NormalizeName(osv.PyPI, name), ver})
	}
	return out
}

// parseGoMod reads the require directives. Since Go 1.17 they list every
// module in the build with its selected version; go.sum would also list
// versions that were never selected.
func parseGoMod(r io.Reader) []appPkg {
	var out []appPkg
	sc := bufio.NewScanner(r)
	block := false
	for sc.Scan() && len(out) < appMaxPackages {
		l := sc.Text()
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		f := strings.Fields(l)
		switch {
		case len(f) == 0:
			continue
		case block && f[0] == ")":
			block = false
			continue
		case !block && f[0] == "require" && len(f) == 2 && f[1] == "(":
			block = true
			continue
		case !block && f[0] == "require":
			f = f[1:]
		case !block:
			continue
		}
		if len(f) == 2 && strings.HasPrefix(f[1], "v") {
			out = append(out, appPkg{osv.Go, f[0], f[1]})
		}
	}
	return out
}

// appInventory turns the manifests into the event data: packages once each
// with the index of the first manifest that has them, within appMaxBytes.
func appInventory(ms []manifest) (map[string]any, string) {
	type key struct{ eco, name, ver string }
	first := map[key]int{}
	var order []key
	var list [][2]any
	for i, m := range ms {
		list = append(list, [2]any{m.Path, len(m.Pkgs)})
		for _, p := range m.Pkgs {
			k := key{p.Eco, p.Name, p.Version}
			if _, ok := first[k]; !ok {
				first[k] = i
				order = append(order, k)
			}
		}
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.eco != b.eco {
			return a.eco < b.eco
		}
		if a.name != b.name {
			return a.name < b.name
		}
		return a.ver < b.ver
	})
	h := sha256.New()
	size := 0
	truncated := false
	var pkgs [][4]any
	for _, k := range order {
		n := len(k.eco) + len(k.name) + len(k.ver) + 16
		if size+n > appMaxBytes {
			truncated = true
			break
		}
		size += n
		pkgs = append(pkgs, [4]any{k.eco, k.name, k.ver, first[k]})
		h.Write([]byte(k.eco + " " + k.name + " " + k.ver + "\n"))
	}
	for _, m := range list {
		h.Write([]byte(m[0].(string) + "\n"))
	}
	sum := hex.EncodeToString(h.Sum(nil))[:16]
	d := map[string]any{"manifests": list, "packages": pkgs, "hash": sum}
	if truncated {
		d["truncated"] = true
	}
	return d, sum
}

func (a *Agent) appRoots() []string {
	if len(a.cfg.AppRoots) > 0 {
		return a.cfg.AppRoots
	}
	return appRootsDefault
}

func (a *Agent) runApps(ctx context.Context) {
	cache := map[string]manifestCache{}
	t := time.NewTimer(6 * time.Minute)
	defer t.Stop()
	var lastHash string
	var lastSent time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		t.Reset(appEvery)
		paths, capped, err := findManifests(ctx, a.appRoots())
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			continue
		}
		var ms []manifest
		next := map[string]manifestCache{}
		for _, p := range paths {
			var st syscall.Stat_t
			if syscall.Stat(p, &st) != nil || st.Size > appMaxFile {
				continue
			}
			c, ok := cache[p]
			if !ok || c.size != st.Size || c.mtime != st.Mtim.Nano() {
				pkgs, err := parseManifest(p)
				if err != nil && len(pkgs) == 0 {
					continue
				}
				c = manifestCache{size: st.Size, mtime: st.Mtim.Nano(), pkgs: pkgs}
			}
			next[p] = c
			if len(c.pkgs) > 0 {
				ms = append(ms, manifest{Path: p, Eco: manifestEco(baseName(p)), Pkgs: c.pkgs})
			}
		}
		cache = next
		d, sum := appInventory(ms)
		if capped {
			d["truncated"] = true
		}
		if sum == lastHash && time.Since(lastSent) < 24*time.Hour {
			continue
		}
		a.emit(proto.NewEvent("system.apps", d))
		lastHash, lastSent = sum, time.Now()
	}
}

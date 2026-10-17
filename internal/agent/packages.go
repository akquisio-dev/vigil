package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/dpkgver"
	"github.com/akquisio-dev/vigil/internal/proto"
)

// Package inventory for vulnerability matching on the server. Debian and
// Ubuntu security data is keyed by source package, so the list holds source
// package names with the newest installed version of each. The agent sends
// it when it changes and once a day; it never contacts a third party.

type srcPkg struct{ Name, Version string }

// sourcePackages reads installed packages from a dpkg status file and maps
// them to source packages ("Source: openssl (3.0.13-0ubuntu3)" or the
// package itself when there is no Source field).
func sourcePackages(path string, newer func(a, b string) bool) []srcPkg {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	best := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256<<10), 4<<20)
	var name, ver, src, srcVer string
	installed := false
	flush := func() {
		if name != "" && installed {
			s, v := name, ver
			if src != "" {
				s = src
			}
			if srcVer != "" {
				v = srcVer
			}
			if cur, ok := best[s]; !ok || newer(v, cur) {
				best[s] = v
			}
		}
		name, ver, src, srcVer, installed = "", "", "", "", false
	}
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "":
			flush()
		case strings.HasPrefix(l, "Package: "):
			name = l[9:]
		case strings.HasPrefix(l, "Version: "):
			ver = l[9:]
		case strings.HasPrefix(l, "Status: "):
			installed = strings.HasSuffix(l, " installed")
		case strings.HasPrefix(l, "Source: "):
			s := strings.TrimSpace(l[8:])
			if n, v, ok := strings.Cut(s, " ("); ok {
				src, srcVer = n, strings.TrimSuffix(v, ")")
			} else {
				src = s
			}
		}
	}
	flush()
	out := make([]srcPkg, 0, len(best))
	for n, v := range best {
		out = append(out, srcPkg{n, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func osRelease() (id, version, codename string) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		case "VERSION_CODENAME":
			codename = v
		}
	}
	return id, version, codename
}

func (a *Agent) runPackages(ctx context.Context) {
	if _, err := os.Stat("/var/lib/dpkg/status"); err != nil {
		return
	}
	t := time.NewTimer(4 * time.Minute)
	defer t.Stop()
	var lastHash string
	var lastSent time.Time
	var lastMtime time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		t.Reset(30 * time.Minute)
		fi, err := os.Stat("/var/lib/dpkg/status")
		if err != nil {
			continue
		}
		if fi.ModTime().Equal(lastMtime) && time.Since(lastSent) < 24*time.Hour {
			continue
		}
		if dpkgBusy() {
			continue
		}
		lastMtime = fi.ModTime()
		pkgs := sourcePackages("/var/lib/dpkg/status", func(a, b string) bool { return dpkgver.Compare(a, b) > 0 })
		list := make([][2]string, len(pkgs))
		h := sha256.New()
		for i, p := range pkgs {
			list[i] = [2]string{p.Name, p.Version}
			h.Write([]byte(p.Name + " " + p.Version + "\n"))
		}
		sum := hex.EncodeToString(h.Sum(nil))
		if sum == lastHash && time.Since(lastSent) < 24*time.Hour {
			continue
		}
		id, ver, code := osRelease()
		a.emit(proto.NewEvent("system.packages", map[string]any{"os_id": id, "os_version": ver, "os_codename": code, "packages": list, "hash": sum[:16]}))
		lastHash, lastSent = sum, time.Now()
	}
}

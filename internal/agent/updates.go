package agent

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Patch state, Debian and Ubuntu: pending updates (security ones counted on
// their own), whether a reboot is pending and whether the running kernel is
// the newest installed one. Everything is read locally; matching against
// vulnerability databases is not done here.

type UpdateState struct {
	FirstSeen   map[string]time.Time `json:"first_seen,omitempty"` // security package -> first seen pending
	RebootSince time.Time            `json:"reboot_since,omitempty"`
}

type aptPending struct {
	name     string
	security bool
}

// parseAptUpgradable reads `apt list --upgradable` output:
// openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
func parseAptUpgradable(out []byte) []aptPending {
	var list []aptPending
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "[upgradable from") {
			continue
		}
		name, rest, ok := strings.Cut(line, "/")
		if !ok {
			continue
		}
		suites := strings.Fields(rest)[0]
		list = append(list, aptPending{name: name, security: strings.Contains(suites, "-security")})
	}
	return list
}

func unattendedEnabled() bool {
	files, _ := filepath.Glob(sysPath("etc/apt/apt.conf.d/*"))
	on := false
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "//") || !strings.HasPrefix(line, "APT::Periodic::Unattended-Upgrade") {
				continue
			}
			on = strings.Contains(line, `"1"`) || strings.Contains(line, `"true"`)
		}
	}
	return on
}

// unameRelease is the running kernel's release, "" when unknown.
func unameRelease() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func kernelVersions() (running, newest string) {
	running = unameRelease()
	files, _ := filepath.Glob(sysPath("boot/vmlinuz-*"))
	var vs []string
	for _, f := range files {
		vs = append(vs, strings.TrimPrefix(filepath.Base(f), "vmlinuz-"))
	}
	sort.Slice(vs, func(i, j int) bool { return versionLess(vs[i], vs[j]) })
	if len(vs) > 0 {
		newest = vs[len(vs)-1]
	}
	return running, newest
}

// versionLess compares kernel release strings numerically part by part.
func versionLess(a, b string) bool {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' })
	}
	pa, pb := split(a), split(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] == pb[i] {
			continue
		}
		na, ea := atoiOK(pa[i])
		nb, eb := atoiOK(pb[i])
		if ea && eb {
			return na < nb
		}
		return pa[i] < pb[i]
	}
	return len(pa) < len(pb)
}

func atoiOK(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func (a *Agent) checkUpdates(ctx context.Context) {
	plat := a.plat()
	pending, supported, err := plat.PendingUpdates(ctx)
	if !supported {
		return
	}
	if err != nil {
		a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "updates", "error": err.Error()}))
		return
	}
	now := time.Now().UTC()
	a.mu.Lock()
	us := &a.state.Updates
	if us.FirstSeen == nil {
		us.FirstSeen = map[string]time.Time{}
	}
	var security []string
	seen := map[string]bool{}
	oldest := now
	for _, p := range pending {
		if !p.security {
			continue
		}
		security = append(security, p.name)
		seen[p.name] = true
		if us.FirstSeen[p.name].IsZero() {
			us.FirstSeen[p.name] = now
		}
		if us.FirstSeen[p.name].Before(oldest) {
			oldest = us.FirstSeen[p.name]
		}
	}
	for k := range us.FirstSeen {
		if !seen[k] {
			delete(us.FirstSeen, k)
		}
	}
	reboot, rebootPkgs := plat.RebootRequired()
	if reboot && us.RebootSince.IsZero() {
		us.RebootSince = now
	} else if !reboot {
		us.RebootSince = time.Time{}
	}
	rebootSince := us.RebootSince
	a.mu.Unlock()

	running, newest := plat.KernelVersions()
	listsAge := plat.ListsAgeDays(now)
	sort.Strings(security)
	if len(security) > 50 {
		security = security[:50]
	}
	d := map[string]any{
		"pending": len(pending), "security": len(security), "security_packages": security,
		"security_oldest_days": int(now.Sub(oldest).Hours() / 24),
		"reboot_required":      reboot, "reboot_packages": rebootPkgs, "kernel_running": running, "kernel_newest": newest,
		"unattended_upgrades": plat.AutoUpdates(), "lists_age_days": listsAge,
	}
	if reboot {
		d["reboot_days"] = int(now.Sub(rebootSince).Hours() / 24)
	}
	a.emit(proto.NewEvent("system.updates", d))
}

func (a *Agent) runUpdates(ctx context.Context) {
	// first check shortly after start, then every six hours
	t := time.NewTimer(2 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			a.checkUpdates(ctx)
			t.Reset(6 * time.Hour)
		}
	}
}

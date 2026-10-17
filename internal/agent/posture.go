package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Posture: settings that make an attack easier before anything happens
// (SSH, accounts, kernel settings, file permissions, firewall), certificates
// close to expiry and backups that stopped arriving. The agent reports the
// full picture every six hours; the server alerts when a check starts to
// fail and closes the alert when it passes again.

const postureEvery = 6 * time.Hour

type postureCheck struct {
	Check string `json:"check"`
	Key   string `json:"key,omitempty"`
	OK    bool   `json:"ok"`
	Value string `json:"value,omitempty"`
	Want  string `json:"want,omitempty"`
}

// Backup is one backup location whose newest file must be younger than
// MaxAgeHours (and at least MinBytes large, when set).
type Backup struct {
	Name        string `json:"name"`
	Path        string `json:"path"` // shell glob; a matching directory counts by its newest entry
	MaxAgeHours int    `json:"max_age_hours"`
	MinBytes    int64  `json:"min_bytes,omitempty"`
}

func (a *Agent) postureReport() map[string]any {
	skip := map[string]bool{}
	for _, s := range a.cfg.PostureSkip {
		skip[s] = true
	}
	var checks []postureCheck
	add := func(cs ...postureCheck) {
		for _, c := range cs {
			if !skip[c.Check] && !skip[c.Check+":"+c.Key] {
				checks = append(checks, c)
			}
		}
	}
	add(sshChecks()...)
	add(accountChecks("/etc/shadow", "/etc/passwd")...)
	add(sysctlChecks("/proc/sys")...)
	add(permissionChecks()...)
	add(firewallCheck()...)
	add(macCheck()...)
	if checks == nil {
		checks = []postureCheck{}
	}
	return map[string]any{"checks": checks, "certs": tlsCerts(a.cfg.TLSCerts, time.Now()), "backups": backupStatus(a.cfg.Backups, time.Now())}
}

// sshdEffective returns sshd's effective settings, from `sshd -T` when it
// works and from the configuration files otherwise (sshd -T fails when
// /run/sshd is missing, which it is inside the agent's sandbox on some hosts).
func sshdEffective() map[string]string {
	sshd := "/usr/sbin/sshd"
	if _, err := os.Stat(sshd); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshd, "-T")
	cmd.Env = []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if out, err := cmd.Output(); err == nil && len(out) > 0 {
		m := map[string]string{}
		for _, line := range strings.Split(string(out), "\n") {
			if k, v, ok := strings.Cut(line, " "); ok {
				m[strings.ToLower(k)] = strings.ToLower(strings.TrimSpace(v))
			}
		}
		return m
	}
	m := map[string]string{}
	parseSshdConfig("/etc/ssh/sshd_config", m, 0)
	defaults := map[string]string{"permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
		"kbdinteractiveauthentication": "yes", "permitemptypasswords": "no", "usepam": "no"}
	for k, v := range defaults {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	if v, ok := m["challengeresponseauthentication"]; ok {
		if _, set := m["kbdinteractiveauthentication"]; !set {
			m["kbdinteractiveauthentication"] = v
		}
	}
	return m
}

// parseSshdConfig keeps the first value of each keyword, follows Include and
// stops at the first Match block, like sshd does for the global settings.
func parseSshdConfig(path string, m map[string]string, depth int) bool {
	if depth > 8 {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(strings.ReplaceAll(line, "=", " "))
		if len(fields) < 2 {
			continue
		}
		k := strings.ToLower(fields[0])
		switch k {
		case "match":
			return true
		case "include":
			for _, pat := range fields[1:] {
				if !filepath.IsAbs(pat) {
					pat = filepath.Join("/etc/ssh", pat)
				}
				files, _ := filepath.Glob(pat)
				sort.Strings(files)
				for _, inc := range files {
					if parseSshdConfig(inc, m, depth+1) {
						return true
					}
				}
			}
			continue
		}
		if _, ok := m[k]; !ok {
			m[k] = strings.ToLower(fields[1])
		}
	}
	return false
}

func sshChecks() []postureCheck {
	m := sshdEffective()
	if m == nil {
		return nil
	}
	pw := m["passwordauthentication"] == "yes" || (m["kbdinteractiveauthentication"] == "yes" && m["usepam"] == "yes")
	return []postureCheck{
		{Check: "ssh_root_login", OK: m["permitrootlogin"] != "yes" || !pw, Value: m["permitrootlogin"], Want: "prohibit-password"},
		{Check: "ssh_password", OK: !pw, Value: "passwordauthentication " + m["passwordauthentication"] + ", kbdinteractiveauthentication " + m["kbdinteractiveauthentication"], Want: "no"},
		{Check: "ssh_empty_password", OK: m["permitemptypasswords"] != "yes", Value: m["permitemptypasswords"], Want: "no"},
	}
}

// accountChecks finds accounts with a login shell and an empty password
// field, which log in (su, console, PAM services) without a password.
func accountChecks(shadow, passwd string) []postureCheck {
	sb, err := os.ReadFile(shadow)
	if err != nil {
		return nil
	}
	shells := map[string]string{}
	if pb, err := os.ReadFile(passwd); err == nil {
		for _, line := range strings.Split(string(pb), "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 7 {
				shells[f[0]] = f[6]
			}
		}
	}
	var empty []string
	for _, line := range strings.Split(string(sb), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 2 || f[0] == "" || f[1] != "" {
			continue
		}
		sh := shells[f[0]]
		if strings.HasSuffix(sh, "nologin") || strings.HasSuffix(sh, "/false") || sh == "" {
			continue
		}
		empty = append(empty, f[0])
	}
	return []postureCheck{{Check: "empty_password", OK: len(empty) == 0, Value: strings.Join(empty, ", ")}}
}

type sysctlWant struct {
	key, check string
	bad        func(string) bool
	want       string
}

var sysctlWants = []sysctlWant{
	{"kernel/randomize_va_space", "aslr", func(v string) bool { return v != "2" }, "2"},
	{"kernel/kptr_restrict", "sysctl", func(v string) bool { return v == "0" }, "1"},
	{"kernel/dmesg_restrict", "sysctl", func(v string) bool { return v == "0" }, "1"},
	{"kernel/yama/ptrace_scope", "sysctl", func(v string) bool { return v == "0" }, "1"},
	{"kernel/unprivileged_bpf_disabled", "sysctl", func(v string) bool { return v == "0" }, "1 or 2"},
	{"fs/protected_symlinks", "sysctl", func(v string) bool { return v == "0" }, "1"},
	{"fs/protected_hardlinks", "sysctl", func(v string) bool { return v == "0" }, "1"},
	{"fs/suid_dumpable", "sysctl", func(v string) bool { return v == "1" }, "0 or 2"},
	{"net/ipv4/conf/all/accept_redirects", "sysctl", func(v string) bool { return v == "1" }, "0"},
	{"net/ipv4/conf/all/accept_source_route", "sysctl", func(v string) bool { return v == "1" }, "0"},
	{"net/ipv4/tcp_syncookies", "sysctl", func(v string) bool { return v == "0" }, "1"},
}

func sysctlChecks(root string) []postureCheck {
	var out []postureCheck
	for _, w := range sysctlWants {
		b, err := os.ReadFile(filepath.Join(root, w.key))
		if err != nil {
			continue // not in this kernel
		}
		v := strings.TrimSpace(string(b))
		name := strings.ReplaceAll(w.key, "/", ".")
		c := postureCheck{Check: w.check, Key: name, OK: !w.bad(v), Value: v, Want: w.want}
		if w.check == "aslr" {
			c.Key = ""
		}
		out = append(out, c)
	}
	return out
}

// permissionChecks looks for files and directories that let a non-root user
// change what root runs or read password hashes.
func permissionChecks() []postureCheck {
	var out []postureCheck
	bad := func(path, why string) {
		out = append(out, postureCheck{Check: "permissions", Key: path, OK: false, Value: why})
	}
	type rule struct {
		glob            string
		noWorldRead     bool
		noGroupWorldW   bool
		groupReadShadow bool
	}
	rules := []rule{
		{"/etc/shadow", true, true, true}, {"/etc/gshadow", true, true, true},
		{"/etc/passwd", false, true, false}, {"/etc/group", false, true, false},
		{"/etc/sudoers", true, true, false}, {"/etc/sudoers.d/*", true, true, false},
		{"/etc/ssh/sshd_config", false, true, false}, {"/etc/ssh/sshd_config.d/*", false, true, false},
		{"/etc/crontab", false, true, false}, {"/etc/cron.d/*", false, true, false},
		{"/etc/pam.d/*", false, true, false}, {"/etc/ld.so.preload", false, true, false},
		{"/etc/systemd/system/*.service", false, true, false},
		{"/root/.ssh/authorized_keys", false, true, false}, {"/root/.ssh", false, true, false}, {"/root", false, true, false},
	}
	for _, r := range rules {
		files, _ := filepath.Glob(r.glob)
		for _, p := range files {
			fi, err := os.Lstat(p)
			if err != nil || fi.Mode()&fs.ModeSymlink != 0 {
				continue
			}
			st, _ := fi.Sys().(*syscall.Stat_t)
			mode := fi.Mode().Perm()
			switch {
			case st != nil && st.Uid != 0:
				bad(p, "owned by uid "+strconv.Itoa(int(st.Uid)))
			case r.noGroupWorldW && mode&0o022 != 0:
				bad(p, "writable by group or others ("+mode.String()+")")
			case r.noWorldRead && mode&0o004 != 0:
				bad(p, "readable by everyone ("+mode.String()+")")
			}
		}
	}
	// PATH directories root uses: writable by others means any user can
	// plant a program root will run.
	for _, d := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		fi, err := os.Stat(d)
		if err != nil {
			continue
		}
		st, _ := fi.Sys().(*syscall.Stat_t)
		if st != nil && st.Uid != 0 {
			bad(d, "owned by uid "+strconv.Itoa(int(st.Uid)))
		} else if fi.Mode().Perm()&0o022 != 0 {
			bad(d, "writable by group or others ("+fi.Mode().Perm().String()+")")
		}
	}
	// World-writable files anywhere in /etc (without following links).
	n := 0
	filepath.WalkDir("/etc", func(p string, d fs.DirEntry, err error) error {
		if err != nil || n > 20000 {
			return nil
		}
		n++
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if fi.Mode().Perm()&0o002 != 0 && (!d.IsDir() || fi.Mode()&fs.ModeSticky == 0) {
			bad(p, "writable by everyone ("+fi.Mode().Perm().String()+")")
		}
		return nil
	})
	if len(out) > 50 {
		out = out[:50]
	}
	// One passing entry, so the server knows the check ran.
	out = append(out, postureCheck{Check: "permissions", Key: "", OK: true})
	return out
}

// firewallCheck reports whether incoming traffic is filtered at all: an
// input chain that drops by policy or has a drop or reject rule.
func firewallCheck() []postureCheck {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	env := []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if nft, err := exec.LookPath("nft"); err == nil {
		cmd := exec.CommandContext(ctx, nft, "list", "ruleset")
		cmd.Env = env
		if out, err := cmd.Output(); err == nil {
			ok, how := nftFilters(out)
			return []postureCheck{{Check: "firewall", OK: ok, Value: how}}
		}
	}
	if ipt, err := exec.LookPath("iptables"); err == nil {
		cmd := exec.CommandContext(ctx, ipt, "-S", "INPUT")
		cmd.Env = env
		if out, err := cmd.Output(); err == nil {
			s := string(out)
			ok := strings.Contains(s, "-P INPUT DROP") || strings.Contains(s, "-j DROP") || strings.Contains(s, "-j REJECT")
			return []postureCheck{{Check: "firewall", OK: ok, Value: map[bool]string{true: "iptables", false: "no input filtering"}[ok]}}
		}
	}
	return nil // cannot tell
}

func nftFilters(ruleset []byte) (bool, string) {
	inInput := false
	depth := 0
	for _, line := range strings.Split(string(ruleset), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "chain ") && strings.HasSuffix(t, "{") {
			inInput, depth = false, 1
			continue
		}
		if depth == 0 {
			continue
		}
		if t == "}" {
			depth = 0
			inInput = false
			continue
		}
		if strings.Contains(t, "hook input") {
			inInput = true
			if strings.Contains(t, "policy drop") {
				return true, "nftables input policy drop"
			}
			continue
		}
		if inInput && (strings.HasSuffix(t, " drop") || strings.Contains(t, " reject") || t == "drop") {
			return true, "nftables input rules"
		}
	}
	return false, "no input filtering"
}

// macCheck: AppArmor or SELinux confining services.
func macCheck() []postureCheck {
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
		on := strings.TrimSpace(string(b)) == "Y"
		return []postureCheck{{Check: "mac", OK: on, Value: "apparmor " + map[bool]string{true: "on", false: "off"}[on]}}
	}
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		on := strings.TrimSpace(string(b)) == "1"
		return []postureCheck{{Check: "mac", OK: on, Value: "selinux " + map[bool]string{true: "enforcing", false: "permissive"}[on]}}
	}
	return []postureCheck{{Check: "mac", OK: false, Value: "none"}}
}

// TLS certificates on disk: Let's Encrypt, what nginx and Apache serve and
// the configured extra globs.

type certInfo struct {
	Path     string    `json:"path"`
	Subject  string    `json:"subject"`
	Names    []string  `json:"names,omitempty"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	Days     int       `json:"days"`
	SelfSign bool      `json:"self_signed,omitempty"`
	Error    string    `json:"error,omitempty"`
}

var webCertConfigs = []struct{ glob, directive string }{
	{"/etc/nginx/nginx.conf", "ssl_certificate"}, {"/etc/nginx/conf.d/*.conf", "ssl_certificate"},
	{"/etc/nginx/sites-enabled/*", "ssl_certificate"},
	{"/etc/apache2/sites-enabled/*", "sslcertificatefile"}, {"/etc/httpd/conf.d/*.conf", "sslcertificatefile"},
}

func certPaths(extra []string) []string {
	seen := map[string]bool{}
	var out []string
	addPath := func(p string) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			real = p
		}
		if !seen[real] {
			seen[real] = true
			out = append(out, p)
		}
	}
	live, _ := filepath.Glob("/etc/letsencrypt/live/*/fullchain.pem")
	for _, p := range live {
		addPath(p)
	}
	for _, wc := range webCertConfigs {
		files, _ := filepath.Glob(wc.glob)
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil || len(b) > 1<<20 {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) >= 2 && strings.ToLower(fields[0]) == wc.directive {
					p := strings.Trim(strings.TrimSuffix(fields[1], ";"), `"'`)
					if filepath.IsAbs(p) && !strings.Contains(p, "$") {
						addPath(p)
					}
				}
			}
		}
	}
	for _, g := range extra {
		files, _ := filepath.Glob(g)
		for _, p := range files {
			addPath(p)
		}
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func readCert(p string, now time.Time) certInfo {
	ci := certInfo{Path: p}
	b, err := os.ReadFile(p)
	if err != nil {
		ci.Error = err.Error()
		return ci
	}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			ci.Error = "no certificate in file"
			return ci
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			ci.Error = err.Error()
			return ci
		}
		ci.Subject = c.Subject.CommonName
		ci.Issuer = c.Issuer.CommonName
		ci.Names = c.DNSNames
		if len(ci.Names) > 5 {
			ci.Names = ci.Names[:5]
		}
		if ci.Subject == "" && len(c.DNSNames) > 0 {
			ci.Subject = c.DNSNames[0]
		}
		ci.NotAfter = c.NotAfter.UTC()
		ci.Days = int(c.NotAfter.Sub(now).Hours() / 24)
		if c.NotAfter.Before(now) {
			ci.Days = -int(now.Sub(c.NotAfter).Hours()/24) - 1
		}
		ci.SelfSign = bytes.Equal(c.RawIssuer, c.RawSubject)
		return ci
	}
}

func tlsCerts(extra []string, now time.Time) []certInfo {
	out := []certInfo{}
	for _, p := range certPaths(extra) {
		out = append(out, readCert(p, now))
	}
	return out
}

type backupInfo struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Newest   string    `json:"newest,omitempty"`
	Modified time.Time `json:"modified,omitempty"`
	AgeHours int       `json:"age_hours"`
	MaxHours int       `json:"max_age_hours"`
	Size     int64     `json:"size"`
	OK       bool      `json:"ok"`
	Problem  string    `json:"problem,omitempty"` // missing | old | small
}

func backupStatus(list []Backup, now time.Time) []backupInfo {
	out := []backupInfo{}
	for _, b := range list {
		bi := backupInfo{Name: b.Name, Path: b.Path, MaxHours: b.MaxAgeHours}
		if bi.Name == "" {
			bi.Name = b.Path
		}
		var newest string
		var newestFI fs.FileInfo
		consider := func(p string, fi fs.FileInfo) {
			if fi.Mode().IsRegular() && (newestFI == nil || fi.ModTime().After(newestFI.ModTime())) {
				newest, newestFI = p, fi
			}
		}
		matches, _ := filepath.Glob(b.Path)
		for _, m := range matches {
			fi, err := os.Stat(m)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				consider(m, fi)
				continue
			}
			entries, _ := os.ReadDir(m)
			for _, e := range entries {
				if efi, err := os.Stat(filepath.Join(m, e.Name())); err == nil {
					consider(filepath.Join(m, e.Name()), efi)
				}
			}
		}
		switch {
		case newestFI == nil:
			bi.Problem = "missing"
		default:
			bi.Newest, bi.Modified, bi.Size = newest, newestFI.ModTime().UTC(), newestFI.Size()
			bi.AgeHours = int(now.Sub(newestFI.ModTime()).Hours())
			if b.MaxAgeHours > 0 && bi.AgeHours >= b.MaxAgeHours {
				bi.Problem = "old"
			} else if b.MinBytes > 0 && bi.Size < b.MinBytes {
				bi.Problem = "small"
			}
		}
		bi.OK = bi.Problem == ""
		out = append(out, bi)
	}
	return out
}

func (a *Agent) runPosture(ctx context.Context) {
	t := time.NewTimer(90 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.emit(proto.NewEvent("posture.report", a.postureReport()))
			t.Reset(postureEvery)
		}
	}
}

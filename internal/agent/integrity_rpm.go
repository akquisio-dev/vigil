package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Integrity on image systems (fedoraatomic): rpm verifies the files of every
// installed package against its own database, which on an image system
// describes the image. /usr is read-only, so a difference there is either a
// writable overlay (`bootc usr-overlay`) or tampering below the file system.
//
// What counts, decided per line of `rpm -Va`:
//
//   - Only paths under /usr. /etc is the admin's: ostree merges it on every
//     update (old defaults, new defaults, local changes), so changed content,
//     modes and owners there are normal. /var and /run are not in the image.
//   - Flags S (size), 5 (digest), M (mode), D (device), L (link target),
//     U (owner), G (group), P (capabilities), and "missing".
//   - T (mtime) never counts: ostree sets every timestamp to the same value,
//     so it differs on every file. --nomtime leaves it out already; a lone T
//     is still ignored in case an rpm prints it anyway.
//   - "?" (could not be checked, e.g. unreadable) is no finding.
//   - Config files (marker c) under /usr: content (S, 5) is ignored like a
//     config file anywhere, mode, owner, group, capabilities, link target and
//     missing still count. Ghost files (g) are not shipped and are ignored.
//
// Like on Debian, a finding is only reported when a second run ten minutes
// later still shows it, and it is reported once: until its flags or its
// SHA-256 change, or it verifies clean and comes back later.

// rpmVerifyArgs: --noscripts keeps rpm from running the packages'
// %verifyscript as root, --nodeps from printing dependency problems,
// --nomtime from printing the timestamps ostree normalised.
var rpmVerifyArgs = []string{"-Va", "--nomtime", "--nodeps", "--noscripts"}

// rpmVerifyLimit is how long one `rpm -Va` may take. It digests every file
// of ~550 packages at the agent's CPU quota and idle I/O priority.
const rpmVerifyLimit = 30 * time.Minute

// rpmFlagNames are the positions of rpm's verify flag field.
var rpmFlagNames = [9]struct {
	c    byte
	name string
}{{'S', "size"}, {'M', "mode"}, {'5', "digest"}, {'D', "device"}, {'L', "link"}, {'U', "owner"}, {'G', "group"}, {'T', "mtime"}, {'P', "capabilities"}}

// rpmVerifyLine is one line of `rpm -Va`: "S.5....T.  c /usr/bin/x" or
// "missing   d /usr/share/doc/x".
type rpmVerifyLine struct {
	flags   string // the flag field, "" when missing
	attr    byte   // file attribute marker (c d g l r), 0 when none
	path    string
	missing bool
}

// parseRPMVerify reads `rpm -Va` output and skips what is not a verify line
// (error and warning messages, dependency problems).
func parseRPMVerify(out []byte) []rpmVerifyLine {
	var list []rpmVerifyLine
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if l, ok := parseRPMVerifyLine(sc.Text()); ok {
			list = append(list, l)
		}
	}
	return list
}

func parseRPMVerifyLine(line string) (rpmVerifyLine, bool) {
	var l rpmVerifyLine
	line = strings.TrimRight(line, "\r\n")
	head, rest, ok := strings.Cut(line, " ")
	if !ok {
		return l, false
	}
	switch {
	case head == "missing":
		l.missing = true
	case rpmFlagField(head):
		l.flags = head
	default:
		return l, false
	}
	rest = strings.TrimLeft(rest, " ")
	if len(rest) > 2 && rest[1] == ' ' && strings.IndexByte("cdglr", rest[0]) >= 0 {
		l.attr = rest[0]
		rest = strings.TrimLeft(rest[2:], " ")
	}
	if !strings.HasPrefix(rest, "/") {
		return l, false
	}
	l.path = rest
	return l, true
}

// rpmFlagField: eight (older rpm, no P) or nine characters, each the
// position's letter, "." or "?".
func rpmFlagField(f string) bool {
	if len(f) != 8 && len(f) != 9 {
		return false
	}
	for i := 0; i < len(f); i++ {
		if f[i] != '.' && f[i] != '?' && f[i] != rpmFlagNames[i].c {
			return false
		}
	}
	return true
}

// rpmReasons names what makes a verify line a finding; nil means none (see
// the rules at the top of this file).
func rpmReasons(l rpmVerifyLine) []string {
	if !strings.HasPrefix(l.path, "/usr/") || l.attr == 'g' {
		return nil
	}
	if l.missing {
		return []string{"missing"}
	}
	var out []string
	for i := 0; i < len(l.flags); i++ {
		c := l.flags[i]
		if c == '.' || c == '?' || c == 'T' {
			continue
		}
		if l.attr == 'c' && (c == 'S' || c == '5') {
			continue
		}
		out = append(out, rpmFlagNames[i].name)
	}
	return out
}

// rpmSuspect is a file rpm -Va reports with at least one counting flag.
type rpmSuspect struct {
	path    string
	flags   string // "missing" or the flag field
	reasons []string
}

func rpmSuspects(out []byte) map[string]rpmSuspect {
	m := map[string]rpmSuspect{}
	for _, l := range parseRPMVerify(out) {
		r := rpmReasons(l)
		if len(r) == 0 {
			continue
		}
		f := l.flags
		if l.missing {
			f = "missing"
		}
		m[l.path] = rpmSuspect{path: l.path, flags: f, reasons: r}
	}
	return m
}

// RPMReported is a finding already reported, kept so it is not reported on
// every run.
type RPMReported struct {
	Flags  string `json:"flags"`
	SHA256 string `json:"sha256,omitempty"`
}

type RPMIntegrityState struct {
	Reported map[string]*RPMReported `json:"reported"`
}

func rpmIntegrityStatePath(dir string) string { return filepath.Join(dir, "integrity-rpm.json") }

func loadRPMIntegrityState(dir string) *RPMIntegrityState {
	is := &RPMIntegrityState{}
	if raw, err := os.ReadFile(rpmIntegrityStatePath(dir)); err == nil {
		json.Unmarshal(raw, is)
	}
	if is.Reported == nil {
		is.Reported = map[string]*RPMReported{}
	}
	return is
}

func (is *RPMIntegrityState) save(dir string) {
	if raw, err := json.Marshal(is); err == nil {
		writeFileAtomic(rpmIntegrityStatePath(dir), raw, 0o600)
	}
}

// rpmFindings turns suspects into findings, leaving out those reported
// before with the same flags and content. Reported files that verify clean
// again are forgotten, so they count anew if they change later.
func rpmFindings(is *RPMIntegrityState, sus map[string]rpmSuspect) []integrityFinding {
	for p := range is.Reported {
		if _, ok := sus[p]; !ok {
			delete(is.Reported, p)
		}
	}
	paths := make([]string, 0, len(sus))
	for p := range sus {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []integrityFinding
	for _, p := range paths {
		s := sus[p]
		d := map[string]any{"path": p, "flags": s.flags, "critical": integrityIsCritical(p),
			"reason": "differs from the rpm database (" + strings.Join(s.reasons, ", ") + ")"}
		sha := ""
		if fi, err := os.Lstat(sysPath(p)); err == nil {
			d["size"] = fi.Size()
			if fi.Mode().IsRegular() {
				if _, h, err := hashFile(sysPath(p)); err == nil {
					sha = h
					d["sha256"] = h
				}
			}
		}
		if s.flags == "missing" {
			d["reason"] = "missing, the rpm database lists it"
		}
		if r := is.Reported[p]; r != nil && r.Flags == s.flags && r.SHA256 == sha {
			continue
		}
		out = append(out, integrityFinding{path: p, data: d, rec: &IntegrityFile{SHA256: sha}})
	}
	return out
}

// rpmVerify runs the platform's verification and tells a usable result from
// a failure. rpm exits non-zero whenever it reports a difference, so an exit
// status with output is a result; one without output, a kill (the time
// limit) or any other error is a failure.
func rpmVerify(ctx context.Context, v packageVerifier) ([]byte, error) {
	out, err := v.VerifyPackages(ctx)
	if err == nil {
		return out, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ee.ExitCode() == -1 {
			return nil, fmt.Errorf("rpm -Va stopped: %v", err)
		}
		if len(out) > 0 {
			return out, nil
		}
		msg := strings.TrimSpace(string(ee.Stderr))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("rpm -Va failed: %v: %s", err, msg)
	}
	return nil, err
}

// rpmIntegrityStep is one run of runRPMIntegrity. Without pending findings
// it is a scan: it reports integrity.scan and returns what it found for
// confirmation. With pending findings it is the confirmation: what still
// shows is reported (at most integrityMaxAlert, then integrity.many) and
// remembered. It returns the pending findings for the next run; ok is false
// when rpm could not be run (warned) or ctx ended.
func (a *Agent) rpmIntegrityStep(ctx context.Context, v packageVerifier, is *RPMIntegrityState, pending map[string]integrityFinding) (map[string]integrityFinding, bool) {
	start := time.Now()
	out, err := rpmVerify(ctx, v)
	if ctx.Err() != nil {
		return nil, false
	}
	if err != nil {
		a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "integrity", "error": err.Error()}))
		return nil, false
	}
	sus := rpmSuspects(out)
	if len(pending) > 0 {
		var again []integrityFinding
		for _, f := range rpmFindings(is, sus) {
			if _, ok := pending[f.path]; ok {
				again = append(again, f)
			}
		}
		for i, f := range again {
			if i == integrityMaxAlert {
				a.emit(proto.NewEvent("integrity.many", map[string]any{"count": len(again)}))
				break
			}
			a.attachRPMOwner(ctx, f.data)
			a.emit(proto.NewEvent("integrity.mismatch", f.data))
			is.Reported[f.path] = &RPMReported{Flags: f.data["flags"].(string), SHA256: f.rec.SHA256}
		}
		is.save(a.cfg.StateDir)
		return nil, true
	}
	found := rpmFindings(is, sus)
	is.save(a.cfg.StateDir)
	scan := map[string]any{"files": 0, "suspect": len(found), "unowned": 0, "first": false,
		"seconds": int(time.Since(start).Seconds()), "verified_by": "rpm"}
	if ov, known := usrOverlayState(ctx); known {
		scan["usr_overlay"] = ov != ""
	}
	a.emit(proto.NewEvent("integrity.scan", scan))
	next := map[string]integrityFinding{}
	for _, f := range found {
		next[f.path] = f
	}
	return next, true
}

// attachRPMOwner fills package and version for an event; rpm -Va does not
// print which package a file belongs to.
func (a *Agent) attachRPMOwner(ctx context.Context, d map[string]any) {
	p, _ := d["path"].(string)
	d["package"], d["version"] = "", ""
	if !filepath.IsAbs(p) {
		return
	}
	out, err := rpmRun(ctx, "-qf", "--queryformat", `%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n`, p)
	if err != nil && len(out) == 0 {
		return
	}
	for _, l := range strings.Split(string(out), "\n") {
		name, evr, ok := strings.Cut(strings.TrimSpace(l), "\t")
		if ok && name != "" && !strings.ContainsAny(name, " /:") {
			d["package"], d["version"] = name, strings.TrimPrefix(evr, "(none):")
			return
		}
	}
}

// runRPMIntegrity is runIntegrity for platforms that verify with rpm: first
// run five minutes after start, then every integrityEvery, a confirmation
// integrityConfirm after a run that found something.
func (a *Agent) runRPMIntegrity(ctx context.Context, v packageVerifier) {
	is := loadRPMIntegrityState(a.cfg.StateDir)
	var pending map[string]integrityFinding
	t := time.NewTimer(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		next, ok := a.rpmIntegrityStep(ctx, v, is, pending)
		if ctx.Err() != nil {
			return
		}
		pending = next
		if ok && len(pending) > 0 {
			t.Reset(integrityConfirm)
		} else {
			t.Reset(integrityEvery)
		}
	}
}

// VerifyPackages runs `rpm -Va` (see rpmVerifyArgs).
func (fedoraAtomicPlatform) VerifyPackages(ctx context.Context) ([]byte, error) {
	return rpmRun(ctx, rpmVerifyArgs...)
}

// usrOverlayState reads bootc's usrOverlay: "" when /usr is the image's
// (null), else a short description of the overlay. known is false without
// bootc or a readable status.
func usrOverlayState(ctx context.Context) (overlay string, known bool) {
	out, err := bootcStatus(ctx)
	if err != nil {
		return "", false
	}
	h, err := parseBootcStatus(out)
	if err != nil {
		return "", false
	}
	return describeOverlay(h.Status.UsrOverlay), true
}

// describeOverlay renders a non-null usrOverlay as "key=value ..." sorted by
// key, for example "accessMode=readWrite persistence=transient".
func describeOverlay(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case map[string]any:
		if len(x) == 0 {
			return "active"
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%v", k, x[k]))
		}
		return strings.Join(parts, " ")
	default:
		if s := fmt.Sprint(x); s != "" {
			return s
		}
		return "active"
	}
}

// PlatformChecks: /usr must be the image's. `bootc usr-overlay` puts a
// writable overlay over it, after which nothing in /usr is vouched for by
// the signed image any more. No check without bootc.
func (fedoraAtomicPlatform) PlatformChecks() []postureCheck {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ov, known := usrOverlayState(ctx)
	if !known {
		return nil
	}
	if ov == "" {
		return []postureCheck{{Check: "usr_overlay", OK: true, Value: "off"}}
	}
	return []postureCheck{{Check: "usr_overlay", OK: false, Value: ov}}
}

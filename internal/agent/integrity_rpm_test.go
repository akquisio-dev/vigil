package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseRPMVerifyLine(t *testing.T) {
	for _, c := range []struct {
		line string
		ok   bool
		want rpmVerifyLine
		why  []string
	}{
		// Shapes seen on a Nyra VM without --nomtime: only T, nothing counts.
		{".......T.    /usr/share/zoneinfo/Africa/Abidjan", true, rpmVerifyLine{flags: ".......T.", path: "/usr/share/zoneinfo/Africa/Abidjan"}, nil},
		{".......T.  l /usr/share/licenses/glibc/COPYING", true, rpmVerifyLine{flags: ".......T.", attr: 'l', path: "/usr/share/licenses/glibc/COPYING"}, nil},
		{"S.5....T.    /usr/bin/ps", true, rpmVerifyLine{flags: "S.5....T.", path: "/usr/bin/ps"}, []string{"size", "digest"}},
		{".M.......    /usr/bin/sudo", true, rpmVerifyLine{flags: ".M.......", path: "/usr/bin/sudo"}, []string{"mode"}},
		{".....UG..    /usr/sbin/sshd", true, rpmVerifyLine{flags: ".....UG..", path: "/usr/sbin/sshd"}, []string{"owner", "group"}},
		{"....L....    /usr/lib64/libc.so.6", true, rpmVerifyLine{flags: "....L....", path: "/usr/lib64/libc.so.6"}, []string{"link"}},
		{"........P    /usr/bin/ping", true, rpmVerifyLine{flags: "........P", path: "/usr/bin/ping"}, []string{"capabilities"}},
		{"missing     /usr/bin/w", true, rpmVerifyLine{missing: true, path: "/usr/bin/w"}, []string{"missing"}},
		{"missing   c /usr/lib/x/defaults.conf", true, rpmVerifyLine{missing: true, attr: 'c', path: "/usr/lib/x/defaults.conf"}, []string{"missing"}},
		{"S.5....T.    /usr/share/My File.txt", true, rpmVerifyLine{flags: "S.5....T.", path: "/usr/share/My File.txt"}, []string{"size", "digest"}},
		// Other markers count like a plain file.
		{".M.......  P /usr/share/x.key", true, rpmVerifyLine{flags: ".M.......", attr: 'P', path: "/usr/share/x.key"}, []string{"mode"}},
		{"....L....  a /usr/lib/.build-id/ab/cdef", true, rpmVerifyLine{flags: "....L....", attr: 'a', path: "/usr/lib/.build-id/ab/cdef"}, []string{"link"}},
		// Config files: content is not a finding, mode still is.
		{"S.5......  c /usr/lib/x/defaults.conf", true, rpmVerifyLine{flags: "S.5......", attr: 'c', path: "/usr/lib/x/defaults.conf"}, nil},
		{".M.......  c /usr/lib/x/defaults.conf", true, rpmVerifyLine{flags: ".M.......", attr: 'c', path: "/usr/lib/x/defaults.conf"}, []string{"mode"}},
		// /etc is merged by ostree and the admin's: never a finding.
		{"S.5....T.  c /etc/ssh/sshd_config", true, rpmVerifyLine{flags: "S.5....T.", attr: 'c', path: "/etc/ssh/sshd_config"}, nil},
		{".M...UG..    /etc/sudoers.d/x", true, rpmVerifyLine{flags: ".M...UG..", path: "/etc/sudoers.d/x"}, nil},
		{"missing     /var/lib/foo", true, rpmVerifyLine{missing: true, path: "/var/lib/foo"}, nil},
		// Ghost files are not shipped; ? could not be checked.
		{"missing   g /usr/lib/ghost", true, rpmVerifyLine{missing: true, attr: 'g', path: "/usr/lib/ghost"}, nil},
		{"..?......    /usr/bin/unreadable", true, rpmVerifyLine{flags: "..?......", path: "/usr/bin/unreadable"}, nil},
		{"S.5....T   /usr/bin/old", true, rpmVerifyLine{flags: "S.5....T", path: "/usr/bin/old"}, []string{"size", "digest"}}, // 8 flags, older rpm
		// Not verify lines.
		{"error: rpmdb: damaged header #42 retrieved -- skipping.", false, rpmVerifyLine{}, nil},
		{"warning: %verify(foo) scriptlet failed", false, rpmVerifyLine{}, nil},
		{"Unsatisfied dependencies for foo-1.0-1.fc44.x86_64:", false, rpmVerifyLine{}, nil},
		{"SXM......    /usr/bin/x", false, rpmVerifyLine{}, nil},
		{"S.5....T.    relative/path", false, rpmVerifyLine{}, nil},
		{"", false, rpmVerifyLine{}, nil},
	} {
		got, ok := parseRPMVerifyLine(c.line)
		if ok != c.ok || (ok && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("%q: %+v %v", c.line, got, ok)
			continue
		}
		if ok && !reflect.DeepEqual(rpmReasons(got), c.why) {
			t.Errorf("%q: reasons %v, want %v", c.line, rpmReasons(got), c.why)
		}
	}
}

// exitOne is a real *exec.ExitError with status 1.
func exitOne(t *testing.T) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit 1").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("no exit status 1: %v", err)
	}
	return err
}

// rpmFake answers -Va with *verify and -qf with a package; --version
// succeeds, so the platform supports integrity.
func rpmFake(t *testing.T, verify *string, calls *[]string) {
	t.Helper()
	rpmRun = func(_ context.Context, args ...string) ([]byte, error) {
		*calls = append(*calls, strings.Join(args, " "))
		switch args[0] {
		case "--version":
			return []byte("RPM version 4.20.1\n"), nil
		case "-Va":
			if *verify == "" {
				return nil, nil
			}
			return []byte(*verify), exitOne(t) // rpm exits 1 when it reports something
		case "-qf":
			return []byte("procps-ng\t(none):4.0.4-7.fc44\n"), nil
		}
		return nil, errors.New("unexpected")
	}
}

func TestFedoraAtomicRPMIntegrity(t *testing.T) {
	root := fedoraAtomicFixture(t)
	var calls []string
	ps := filepath.Join(root, "usr/bin/ps")
	os.MkdirAll(filepath.Dir(ps), 0o755)
	os.WriteFile(ps, []byte("evil"), 0o755)
	var verify string
	rpmFake(t, &verify, &calls)

	p := fedoraAtomicPlatform{}
	if why := p.IntegrityUnsupported(); why != "" {
		t.Fatalf("rpm present, still unsupported: %s", why)
	}
	if !reflect.DeepEqual(rpmVerifyArgs, []string{"-Va", "--nomtime", "--nodeps", "--noscripts"}) {
		t.Fatalf("args %v", rpmVerifyArgs)
	}
	a := &Agent{cfg: &Config{MaxQueue: 1000, StateDir: t.TempDir()}, platform: p}
	is := loadRPMIntegrityState(a.cfg.StateDir)
	ctx := context.Background()

	verify = ".......T.    /usr/share/zoneinfo/Africa/Abidjan\n" +
		"S.5....T.    /usr/bin/ps\n" +
		".M.......    /usr/bin/vigil-test-not-there\n" +
		"S.5....T.  c /etc/ssh/sshd_config\n"
	pending, ok := a.rpmIntegrityStep(ctx, p, is, nil)
	if !ok || len(pending) != 2 {
		t.Fatalf("scan pending: %v", pending)
	}
	if len(a.queue) != 1 || a.queue[0].Type != "integrity.scan" || a.queue[0].Data["suspect"] != 2 {
		t.Fatalf("scan events: %+v", a.queue)
	}

	// Confirmation: only what is still there and was pending is reported.
	verify = "S.5....T.    /usr/bin/ps\n" + "S.5....T.    /usr/bin/new-since\n"
	a.queue = nil
	pending, ok = a.rpmIntegrityStep(ctx, p, is, pending)
	if !ok || pending != nil {
		t.Fatalf("confirm pending: %v", pending)
	}
	if len(a.queue) != 1 || a.queue[0].Type != "integrity.mismatch" {
		t.Fatalf("confirm events: %+v", a.queue)
	}
	d := a.queue[0].Data
	if d["path"] != "/usr/bin/ps" || d["critical"] != true || d["package"] != "procps-ng" || d["version"] != "4.0.4-7.fc44" ||
		d["flags"] != "S.5....T." || d["sha256"] != "b5c1fb2efc6d6b4674c2fdcc48ce01b43a3b7c03763c0c3355de0099ee0f8c73" || !strings.Contains(d["reason"].(string), "size, digest") {
		t.Fatalf("mismatch: %+v", d)
	}

	// Reported once: the same finding again is not pending.
	verify = "S.5....T.    /usr/bin/ps\n"
	a.queue = nil
	if pending, _ = a.rpmIntegrityStep(ctx, p, loadRPMIntegrityState(a.cfg.StateDir), nil); len(pending) != 0 {
		t.Fatalf("reported again: %v", pending)
	}
	// Flags change: a new finding.
	verify = "SM5....T.    /usr/bin/ps\n"
	if pending, _ = a.rpmIntegrityStep(ctx, p, loadRPMIntegrityState(a.cfg.StateDir), nil); len(pending) != 1 {
		t.Fatalf("changed flags not pending: %v", pending)
	}

	// rpm failing without output is a warning, not a clean run.
	rpmRun = func(_ context.Context, args ...string) ([]byte, error) {
		return nil, exitOne(t)
	}
	a.queue = nil
	if _, ok := a.rpmIntegrityStep(ctx, p, is, nil); ok || len(a.queue) != 1 || a.queue[0].Type != "agent.warning" {
		t.Fatalf("failure: %v %+v", ok, a.queue)
	}
	// Killed (the time limit): partial output is thrown away.
	killed := exec.Command("sh", "-c", "kill -9 $$").Run()
	rpmRun = func(_ context.Context, args ...string) ([]byte, error) {
		return []byte("S.5....T.    /usr/bin/ps\n"), killed
	}
	a.queue = nil
	if pending, ok := a.rpmIntegrityStep(ctx, p, is, nil); ok || pending != nil || len(a.queue) != 1 || a.queue[0].Type != "agent.warning" {
		t.Fatalf("killed: %v %+v", ok, a.queue)
	}
}

func TestFedoraAtomicRPMIntegrityCap(t *testing.T) {
	fedoraAtomicFixture(t)
	var calls []string
	var b strings.Builder
	for i := 0; i < integrityMaxAlert+5; i++ {
		b.WriteString("S.5....T.    /usr/lib/vigil-test/f" + string(rune('a'+i%26)) + strings.Repeat("x", i) + "\n")
	}
	verify := b.String()
	rpmFake(t, &verify, &calls)
	p := fedoraAtomicPlatform{}
	a := &Agent{cfg: &Config{MaxQueue: 1000, StateDir: t.TempDir()}, platform: p}
	is := loadRPMIntegrityState(a.cfg.StateDir)
	pending, _ := a.rpmIntegrityStep(context.Background(), p, is, nil)
	a.queue = nil
	a.rpmIntegrityStep(context.Background(), p, is, pending)
	n := 0
	for _, ev := range a.queue {
		switch ev.Type {
		case "integrity.mismatch":
			n++
		case "integrity.many":
			if ev.Data["count"] != integrityMaxAlert+5 {
				t.Fatalf("many: %+v", ev.Data)
			}
		}
	}
	if n != integrityMaxAlert || a.queue[len(a.queue)-1].Type != "integrity.many" {
		t.Fatalf("%d mismatches, last %s", n, a.queue[len(a.queue)-1].Type)
	}
}

// runIntegrity hands fedoraatomic with rpm to the rpm loop, which waits for
// its first run instead of warning and stopping.
func TestFedoraAtomicRunsRPMIntegrity(t *testing.T) {
	fedoraAtomicFixture(t)
	var calls []string
	verify := ""
	rpmFake(t, &verify, &calls)
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: t.TempDir()}, platform: fedoraAtomicPlatform{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.runIntegrity(ctx); close(done) }()
	cancel()
	<-done
	if len(a.queue) != 0 {
		t.Fatalf("events: %+v", a.queue)
	}
	if _, ok := Platform(debianPlatform{}).(packageVerifier); ok {
		t.Fatal("debian must keep its own integrity check")
	}
}

func TestFedoraAtomicUsrOverlay(t *testing.T) {
	fedoraAtomicFixture(t)
	real, err := os.ReadFile("testdata/bootc-status-nyra.json")
	if err != nil {
		t.Fatal(err)
	}
	p := fedoraAtomicPlatform{}
	if got := p.PlatformChecks(); got != nil {
		t.Fatalf("without bootc: %+v", got)
	}
	bootcStatus = func(context.Context) ([]byte, error) { return real, nil }
	if got := p.PlatformChecks(); !reflect.DeepEqual(got, []postureCheck{{Check: "usr_overlay", OK: true, Value: "off"}}) {
		t.Fatalf("real null overlay: %+v", got)
	}
	if !strings.Contains(string(real), `"usrOverlay":null`) {
		t.Fatal("testdata changed")
	}
	over := strings.Replace(string(real), `"usrOverlay":null`, `"usrOverlay":{"accessMode":"readWrite","persistence":"transient"}`, 1)
	bootcStatus = func(context.Context) ([]byte, error) { return []byte(over), nil }
	want := []postureCheck{{Check: "usr_overlay", OK: false, Value: "accessMode=readWrite persistence=transient"}}
	if got := p.PlatformChecks(); !reflect.DeepEqual(got, want) {
		t.Fatalf("overlay: %+v", got)
	}
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: t.TempDir()}, platform: p}
	found := false
	for _, c := range a.postureReport()["checks"].([]postureCheck) {
		found = found || c.Check == "usr_overlay" && !c.OK
	}
	if !found {
		t.Fatal("overlay missing from the posture report")
	}
	if _, ok := Platform(debianPlatform{}).(platformPosture); ok {
		t.Fatal("debian has no platform checks")
	}
}

// TestRPMDirectoryModeOnCleanImage: the lines a clean Nyra image prints
// (directories with ostree's mode) are no findings; a directory that became
// group or world writable still is, and so is a mode change on a file.
func TestRPMDirectoryModeOnCleanImage(t *testing.T) {
	root := t.TempDir()
	old := sysRoot
	sysRoot = root
	t.Cleanup(func() { sysRoot = old })
	mk := func(rel string, mode os.FileMode, dir bool) {
		p := filepath.Join(root, rel)
		if dir {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
		} else {
			os.MkdirAll(filepath.Dir(p), 0o755)
			if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	mk("usr/bin", 0o755, true)
	mk("usr/lib64/bpf", 0o755, true)
	mk("usr/share/open", 0o777, true)
	mk("usr/bin/tool", 0o755, false)
	out := []byte(".M.......    /usr/bin\n.M.......    /usr/lib64/bpf\n.M.......    /usr/share/open\n.M.......    /usr/bin/tool\nmissing     /afs\n")
	sus := rpmSuspects(out)
	if _, ok := sus["/usr/bin"]; ok {
		t.Error("/usr/bin with ostree's mode must not be a finding")
	}
	if _, ok := sus["/usr/lib64/bpf"]; ok {
		t.Error("/usr/lib64/bpf must not be a finding")
	}
	if _, ok := sus["/usr/share/open"]; !ok {
		t.Error("a world writable directory is a finding")
	}
	if _, ok := sus["/usr/bin/tool"]; !ok {
		t.Error("a mode change on a file is a finding")
	}
	if _, ok := sus["/afs"]; ok {
		t.Error("paths outside /usr are ignored")
	}
}

// nyraCleanVerify is what `rpm -Va --nomtime --nodeps --noscripts` printed
// under /usr on a clean Nyra image (Fedora 44 bootc, 2026-11-05), shortened:
// files the image build removes or changes, bytecode compiled again, ghost
// files.
const nyraCleanVerify = `missing     /usr/lib/systemd/system/sysinit.target.wants/systemd-firstboot.service
missing     /usr/lib/tmpfiles.d/home.conf
missing     /usr/lib/systemd/system/grub-boot-indeterminate.service
missing     /usr/lib/systemd/system/grub2-systemd-integration.service
missing     /usr/lib/systemd/system/reboot.target.wants
missing     /usr/lib/systemd/system/reboot.target.wants/grub2-systemd-integration.service
missing     /usr/lib/systemd/system/system-update.target.wants/grub-boot-indeterminate.service
missing     /usr/lib/systemd/system/systemd-logind.service.d
missing     /usr/lib/systemd/system/systemd-logind.service.d/10-grub2-logind-service.conf
missing     /usr/lib/systemd/user/grub-boot-success.service
missing     /usr/lib/systemd/user/grub-boot-success.timer
S.5......    /usr/lib/tmpfiles.d/provision.conf
S.5......    /usr/lib/kernel/install.conf
S.5......    /usr/lib64/python3.14/__pycache__/abc.cpython-314.pyc
..5......    /usr/lib64/python3.14/__pycache__/os.cpython-314.opt-1.pyc
.M.......  g /usr/lib/sysimage/rpm-ostree-base-db
.M.......  g /var/log/lastlog
`

func nyraBootc(t *testing.T, digest *string) {
	t.Helper()
	real, err := os.ReadFile("testdata/bootc-status-nyra.json")
	if err != nil {
		t.Fatal(err)
	}
	const was = "sha256:8f624888672f84727dd35824982e88ae6a584215589ddfb8fa0d72f378b663f9"
	if !strings.Contains(string(real), was) {
		t.Fatal("testdata changed")
	}
	bootcStatus = func(context.Context) ([]byte, error) {
		return []byte(strings.Replace(string(real), was, *digest, 1)), nil
	}
}

// TestRPMImageBaseline: the first scan of a booted image takes its rpm -Va
// output as the reference and reports nothing; later scans report what is
// new or changed against it; a new image starts a new baseline.
func TestRPMImageBaseline(t *testing.T) {
	root := fedoraAtomicFixture(t)
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("usr/lib/tmpfiles.d/provision.conf", "image build\n")
	write("usr/lib/kernel/install.conf", "layout=ostree\n")
	write("usr/lib64/python3.14/__pycache__/abc.cpython-314.pyc", "bytecode 1")
	write("usr/lib64/python3.14/__pycache__/os.cpython-314.opt-1.pyc", "bytecode 2")
	write("usr/bin/ps", "procps")
	var calls []string
	verify := nyraCleanVerify
	rpmFake(t, &verify, &calls)
	digest := "sha256:aaaa"
	nyraBootc(t, &digest)
	p := fedoraAtomicPlatform{}
	a := &Agent{cfg: &Config{MaxQueue: 1000, StateDir: t.TempDir()}, platform: p}
	ctx := context.Background()
	step := func(pending map[string]integrityFinding) map[string]integrityFinding {
		t.Helper()
		a.queue = nil
		next, ok := a.rpmIntegrityStep(ctx, p, loadRPMIntegrityState(a.cfg.StateDir), pending)
		if !ok {
			t.Fatalf("step failed: %+v", a.queue)
		}
		return next
	}

	// First scan of the image: only integrity.baseline, nothing pending.
	if pending := step(nil); len(pending) != 0 {
		t.Fatalf("baseline scan pending: %v", pending)
	}
	if len(a.queue) != 1 || a.queue[0].Type != "integrity.baseline" {
		t.Fatalf("baseline events: %+v", a.queue)
	}
	d := a.queue[0].Data
	if d["image"] != digest || d["suspects"] != 15 || d["missing"] != 11 || d["changed"] != 4 {
		t.Fatalf("baseline counts: %+v", d)
	}
	is := loadRPMIntegrityState(a.cfg.StateDir)
	if is.Version != rpmIntegrityStateVersion || is.Image != digest || len(is.Baseline) != 15 ||
		is.Baseline["/usr/lib/kernel/install.conf"].SHA256 == "" || is.Baseline["/usr/lib/tmpfiles.d/home.conf"].Flags != "missing" {
		t.Fatalf("state: %+v", is)
	}

	// The same output again: a clean scan.
	if pending := step(nil); len(pending) != 0 || len(a.queue) != 1 || a.queue[0].Type != "integrity.scan" ||
		a.queue[0].Data["suspect"] != 0 || a.queue[0].Data["baseline"] != 15 || a.queue[0].Data["usr_overlay"] != false {
		t.Fatalf("clean image again: %v %+v", pending, a.queue)
	}

	// A file the baseline does not know: pending, then reported.
	verify = nyraCleanVerify + "S.5......    /usr/bin/ps\n"
	write("usr/bin/ps", "evil")
	pending := step(nil)
	if len(pending) != 1 || pending["/usr/bin/ps"].path == "" {
		t.Fatalf("new finding: %v", pending)
	}
	step(pending)
	if len(a.queue) != 1 || a.queue[0].Type != "integrity.mismatch" || a.queue[0].Data["path"] != "/usr/bin/ps" {
		t.Fatalf("confirm: %+v", a.queue)
	}

	// A baselined file with other content, and one with other flags.
	write("usr/lib64/python3.14/__pycache__/abc.cpython-314.pyc", "bytecode 1, changed")
	verify = strings.Replace(nyraCleanVerify, "..5......    /usr/lib64/python3.14/__pycache__/os", "SM5......    /usr/lib64/python3.14/__pycache__/os", 1) +
		"S.5......    /usr/bin/ps\n"
	pending = step(nil)
	if len(pending) != 2 || pending["/usr/lib64/python3.14/__pycache__/abc.cpython-314.pyc"].path == "" ||
		pending["/usr/lib64/python3.14/__pycache__/os.cpython-314.opt-1.pyc"].path == "" {
		t.Fatalf("changed baseline files: %v", pending)
	}

	// An update (or rollback) boots another image: a new baseline, nothing
	// reported, findings of the old image forgotten.
	digest = "sha256:bbbb"
	if pending := step(nil); len(pending) != 0 || len(a.queue) != 1 || a.queue[0].Type != "integrity.baseline" || a.queue[0].Data["suspects"] != 16 {
		t.Fatalf("new image: %v %+v", pending, a.queue)
	}
	if is := loadRPMIntegrityState(a.cfg.StateDir); is.Image != digest || len(is.Reported) != 0 || is.Baseline["/usr/bin/ps"] == nil {
		t.Fatalf("new image state: %+v", is)
	}

	// With a writable /usr overlay no baseline is taken: what was changed
	// through it would become the reference. The old image's baseline does
	// not apply either.
	digest = "sha256:cccc"
	over, _ := os.ReadFile("testdata/bootc-status-nyra.json")
	over = []byte(strings.Replace(strings.Replace(string(over), "sha256:8f624888672f84727dd35824982e88ae6a584215589ddfb8fa0d72f378b663f9", digest, 1),
		`"usrOverlay":null`, `"usrOverlay":{"accessMode":"readWrite","persistence":"transient"}`, 1))
	bootcStatus = func(context.Context) ([]byte, error) { return over, nil }
	verify = nyraCleanVerify
	if pending := step(nil); len(pending) != 15 || a.queue[0].Type != "integrity.scan" || a.queue[0].Data["usr_overlay"] != true {
		t.Fatalf("overlay: %d %+v", len(pending), a.queue)
	}
	if is := loadRPMIntegrityState(a.cfg.StateDir); is.Image != "sha256:bbbb" {
		t.Fatalf("baseline taken under an overlay: %+v", is.Image)
	}
}

// A version 1 state file (no version, no baseline) keeps its reported
// findings and gets a baseline on the next scan that knows the image.
func TestRPMStateV1Migrates(t *testing.T) {
	fedoraAtomicFixture(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "integrity-rpm.json"), []byte(`{"reported":{"/usr/bin/ps":{"flags":"S.5......","sha256":"ab"}}}`), 0o600)
	is := loadRPMIntegrityState(dir)
	if is.Version != rpmIntegrityStateVersion || is.Image != "" || is.Baseline != nil || is.Reported["/usr/bin/ps"].SHA256 != "ab" {
		t.Fatalf("v1: %+v", is)
	}
	var calls []string
	verify := nyraCleanVerify
	rpmFake(t, &verify, &calls)
	digest := "sha256:aaaa"
	nyraBootc(t, &digest)
	p := fedoraAtomicPlatform{}
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: dir}, platform: p}
	if pending, _ := a.rpmIntegrityStep(context.Background(), p, is, nil); len(pending) != 0 || a.queue[0].Type != "integrity.baseline" {
		t.Fatalf("first scan after the update: %v %+v", pending, a.queue)
	}
}

// Without an image digest bootc's ostree commit names the deployment.
func TestBootedImageID(t *testing.T) {
	real, _ := os.ReadFile("testdata/bootc-status-nyra.json")
	h, err := parseBootcStatus(real)
	if err != nil || bootedImageID(h) != "sha256:8f624888672f84727dd35824982e88ae6a584215589ddfb8fa0d72f378b663f9" {
		t.Fatalf("digest: %v %q", err, bootedImageID(h))
	}
	h.Status.Booted.Image = nil
	if got := bootedImageID(h); got != "ostree:6703c47ddb789b5ea6c4cf0e425ed171b4a673b0c53888ee927a462be6ed63db" {
		t.Fatalf("ostree: %q", got)
	}
	h.Status.Booted = nil
	if bootedImageID(h) != "" {
		t.Fatal("no booted deployment")
	}
}

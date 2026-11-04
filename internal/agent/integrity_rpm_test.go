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

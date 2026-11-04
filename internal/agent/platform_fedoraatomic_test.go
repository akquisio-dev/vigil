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
	"time"
)

// fedoraAtomicFixture builds a small Fedora bootc tree, points sysRoot at it
// and replaces rpm and bootc with canned output. Nothing here needs rpm or
// bootc on the test host.
func fedoraAtomicFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("run/ostree-booted", "")
	write("etc/os-release", "NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=44\nVARIANT_ID=bootc\n")
	write("usr/lib/sysimage/rpm/rpmdb.sqlite", "")
	write("usr/lib/modules/6.17.4-300.fc44.x86_64/vmlinuz", "")
	write("usr/lib/modules/6.9.1-200.fc44.x86_64/vmlinuz", "")
	write("usr/lib/modules/7.0.0-extra/modules.dep", "") // no vmlinuz: not a kernel
	write("sys/fs/selinux/enforce", "1")
	oldRoot, oldRPM, oldBootc := sysRoot, rpmRun, bootcStatus
	sysRoot = root
	rpmRun = func(context.Context, ...string) ([]byte, error) { return nil, exec.ErrNotFound }
	bootcStatus = func(context.Context) ([]byte, error) { return nil, exec.ErrNotFound }
	t.Cleanup(func() { sysRoot, rpmRun, bootcStatus = oldRoot, oldRPM, oldBootc })
	return root
}

func TestFedoraAtomicDetection(t *testing.T) {
	root := fedoraAtomicFixture(t)
	for _, c := range []struct{ conf, id, like, want string }{
		{"", "fedora", "", "fedoraatomic"},
		{"", "nyra", "fedora", "fedoraatomic"}, // a derived image names Fedora in ID_LIKE
		{"", "ubuntu", "debian", "debian"},
		{"debian", "fedora", "", "debian"},
		{"fedoraatomic", "ubuntu", "", "fedoraatomic"},
	} {
		p, err := choosePlatform(c.conf, c.id, c.like)
		if err != nil || p.Name() != c.want {
			t.Fatalf("%+v: %v %v", c, p, err)
		}
	}
	if p := platformFor(&Config{}); p.Name() != "fedoraatomic" {
		t.Fatalf("from the fixture's os-release: %s", p.Name())
	}
	os.Remove(filepath.Join(root, "run/ostree-booted"))
	if p, _ := choosePlatform("", "fedora", ""); p.Name() != "debian" {
		t.Fatalf("classic Fedora: %s", p.Name())
	}
	cfg := filepath.Join(t.TempDir(), "agent.json")
	os.WriteFile(cfg, []byte(`{"server":"https://x","platform":"fedoraatomic"}`), 0o600)
	if c, err := LoadConfig(cfg); err != nil || c.Platform != "fedoraatomic" {
		t.Fatalf("fedoraatomic refused: %v", err)
	}
}

func TestParseRPMSources(t *testing.T) {
	out := "openssl-3.2.2-3.fc44.src.rpm\t1:3.2.2-3.fc44\n" +
		"openssl-3.2.2-3.fc44.src.rpm\t1:3.2.2-3.fc44\n" + // openssl-libs, same source
		"python-requests-2.32.3-4.fc44.src.rpm\t(none):2.32.3-4.fc44\n" +
		"kernel-6.9.1-200.fc44.src.rpm\t(none):6.9.1-200.fc44\n" +
		"kernel-6.17.4-300.fc44.src.rpm\t(none):6.17.4-300.fc44\n" +
		"(none)\t(none):d2382de1-1a2b3c4d\n" + // gpg-pubkey
		"foo-1.0-1.nosrc.rpm\t(none):1.0-1\n" +
		"broken.src.rpm\t(none):1-1\n" +
		"no tab here\n"
	got := parseRPMSources([]byte(out))
	want := []srcPkg{{"foo", "1.0-1"}, {"kernel", "6.17.4-300.fc44"}, {"openssl", "1:3.2.2-3.fc44"}, {"python-requests", "2.32.3-4.fc44"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestFedoraAtomicPackages(t *testing.T) {
	root := fedoraAtomicFixture(t)
	p := fedoraAtomicPlatform{}
	stamp, err := p.PackageDBStamp()
	fi, _ := os.Stat(filepath.Join(root, "usr/lib/sysimage/rpm/rpmdb.sqlite"))
	if err != nil || !stamp.Equal(fi.ModTime()) {
		t.Fatalf("stamp: %v %v", stamp, err)
	}
	os.Remove(filepath.Join(root, "usr/lib/sysimage/rpm/rpmdb.sqlite"))
	if _, err := p.PackageDBStamp(); err == nil {
		t.Fatal("no rpm database must be an error")
	}
	os.MkdirAll(filepath.Join(root, "var/lib/rpm"), 0o755)
	os.WriteFile(filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), nil, 0o644)
	if _, err := p.PackageDBStamp(); err != nil {
		t.Fatalf("fallback to /var/lib/rpm: %v", err)
	}
	if p.SourcePackages() != nil || p.Owners([]string{"/usr/bin/ls"}).ok {
		t.Fatal("without rpm there is nothing")
	}
	var calls [][]string
	rpmRun = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if args[0] == "-qa" {
			return []byte("bash-5.2.37-1.fc44.src.rpm\t(none):5.2.37-1.fc44\n"), nil
		}
		switch args[len(args)-1] {
		case "/usr/bin/sudo":
			return []byte("sudo\n"), nil
		case "/usr/bin/su":
			return []byte("util-linux\nutil-linux-core\n"), nil // owned twice
		case "/usr/bin/vigil-agent":
			return []byte("vigil-agent\n"), nil
		}
		return []byte("file " + args[len(args)-1] + " is not owned by any package\n"), errors.New("exit status 1")
	}
	if got := p.SourcePackages(); !reflect.DeepEqual(got, []srcPkg{{"bash", "5.2.37-1.fc44"}}) {
		t.Fatalf("%v", got)
	}
	if !reflect.DeepEqual(calls[0], []string{"-qa", "--queryformat", `%{SOURCERPM}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n`}) {
		t.Fatalf("rpm -qa arguments: %q", calls[0])
	}
	info := p.Owners([]string{"/usr/bin/sudo", "/usr/bin/su", "/usr/local/bin/x", "relative"})
	if !info.ok || !reflect.DeepEqual(info.owner, map[string]string{"/usr/bin/sudo": "sudo", "/usr/bin/su": "util-linux"}) {
		t.Fatalf("owners: %+v", info)
	}
	for _, c := range calls {
		if c[len(c)-1] == "relative" {
			t.Fatal("a relative path reached rpm")
		}
	}
	if p.SelfOwner("/usr/bin/vigil-agent") != "vigil-agent" || p.SelfOwner("/opt/vigil/vigil-agent") != "" {
		t.Fatal("self owner")
	}
	if p.Busy() || len(p.PackagedFiles()) != 0 {
		t.Fatal("busy or packaged files")
	}
}

func TestParseRPMOwner(t *testing.T) {
	for in, want := range map[string]string{
		"sudo\n":                                      "sudo",
		"util-linux\nutil-linux-core\n":               "util-linux",
		"file /x is not owned by any package\n":       "",
		"error: file /x: No such file or directory\n": "",
		"": "",
	} {
		if got := parseRPMOwner([]byte(in)); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

const bootcIdle = `{"apiVersion":"org.containers.bootc/v1","kind":"BootcHost","status":{"staged":null,
"booted":{"image":{"image":{"image":"ghcr.io/nyra/nyra","transport":"registry"},"version":"44.20261101.0","imageDigest":"sha256:aaa"},"cachedUpdate":null},
"rollback":{"image":{"image":{"image":"ghcr.io/nyra/nyra","transport":"registry"},"version":"44.20261020.0","imageDigest":"sha256:999"}}}}`

const bootcStaged = `{"status":{"staged":{"image":{"image":{"image":"ghcr.io/nyra/nyra"},"version":"44.20261104.0","imageDigest":"sha256:bbb"}},
"booted":{"image":{"image":{"image":"ghcr.io/nyra/nyra"},"version":"44.20261101.0","imageDigest":"sha256:aaa"}},"rollback":null}}`

const bootcCached = `{"status":{"staged":null,
"booted":{"image":{"image":{"image":"ghcr.io/nyra/nyra"},"version":"44.20261101.0","imageDigest":"sha256:aaa"},
"cachedUpdate":{"image":{"image":"ghcr.io/nyra/nyra"},"version":"44.20261103.0","imageDigest":"sha256:ccc"}}}}`

func TestFedoraAtomicUpdates(t *testing.T) {
	root := fedoraAtomicFixture(t)
	p := fedoraAtomicPlatform{}
	ctx := context.Background()
	if _, supported, _ := p.PendingUpdates(ctx); supported {
		t.Fatal("without bootc updates are not supported")
	}
	if r, _ := p.RebootRequired(); r {
		t.Fatal("reboot without bootc")
	}
	status := bootcIdle
	bootcStatus = func(context.Context) ([]byte, error) { return []byte(status), nil }
	if l, supported, err := p.PendingUpdates(ctx); !supported || err != nil || len(l) != 0 {
		t.Fatalf("idle: %v %v %v", l, supported, err)
	}
	if r, _ := p.RebootRequired(); r {
		t.Fatal("idle needs no reboot")
	}
	status = bootcStaged
	if l, _, _ := p.PendingUpdates(ctx); !reflect.DeepEqual(l, []aptPending{{name: "image 44.20261104.0"}}) {
		t.Fatalf("staged: %+v", l)
	}
	if r, pk := p.RebootRequired(); !r || !reflect.DeepEqual(pk, []string{"image 44.20261104.0"}) {
		t.Fatalf("staged reboot: %v %v", r, pk)
	}
	status = bootcCached
	if l, _, _ := p.PendingUpdates(ctx); !reflect.DeepEqual(l, []aptPending{{name: "image 44.20261103.0"}}) {
		t.Fatalf("cached: %+v", l)
	}
	if r, _ := p.RebootRequired(); r {
		t.Fatal("a fetched but unstaged update needs no reboot yet")
	}
	status = `{"status":{"staged":{"image":null},"booted":{"image":null}}}`
	if r, pk := p.RebootRequired(); !r || !reflect.DeepEqual(pk, []string{"image"}) {
		t.Fatalf("staged without version: %v %v", r, pk)
	}
	status = `{"status":{"staged":null,"booted":null}}`
	if _, supported, _ := p.PendingUpdates(ctx); supported {
		t.Fatal("not booted through bootc")
	}
	status = "not json"
	if _, supported, err := p.PendingUpdates(ctx); !supported || err == nil {
		t.Fatal("broken output is an error")
	}
	bootcStatus = func(context.Context) ([]byte, error) { return nil, errors.New("exit status 1") }
	if _, supported, err := p.PendingUpdates(ctx); !supported || err == nil {
		t.Fatal("a failing bootc is an error")
	}

	running, newest := p.KernelVersions()
	if running != unameRelease() || newest != "6.17.4-300.fc44.x86_64" {
		t.Fatalf("kernel %q %q", running, newest)
	}
	if p.ListsAgeDays(time.Now()) != -1 {
		t.Fatal("no lists on image systems")
	}

	if p.AutoUpdates() {
		t.Fatal("timer not enabled in the fixture")
	}
	const timer = "bootc-fetch-apply-updates.timer"
	usrWants := filepath.Join(root, "usr/lib/systemd/system/timers.target.wants")
	os.MkdirAll(usrWants, 0o755)
	os.Symlink("../"+timer, filepath.Join(usrWants, timer)) // dangling in the fixture: Lstat
	if !p.AutoUpdates() {
		t.Fatal("enabled by the image")
	}
	etc := filepath.Join(root, "etc/systemd/system")
	os.MkdirAll(etc, 0o755)
	os.Symlink("/dev/null", filepath.Join(etc, timer))
	if p.AutoUpdates() {
		t.Fatal("masked")
	}
	os.Remove(filepath.Join(etc, timer))
	os.Remove(filepath.Join(usrWants, timer))
	os.MkdirAll(filepath.Join(etc, "timers.target.wants"), 0o755)
	os.Symlink("/usr/lib/systemd/system/"+timer, filepath.Join(etc, "timers.target.wants", timer))
	if !p.AutoUpdates() {
		t.Fatal("enabled by the admin")
	}
}

func TestFedoraAtomicPosture(t *testing.T) {
	root := fedoraAtomicFixture(t)
	p := fedoraAtomicPlatform{}
	enforce := filepath.Join(root, "sys/fs/selinux/enforce")
	for body, want := range map[string]postureCheck{
		"1":   {Check: "mac", OK: true, Value: "selinux enforcing"},
		"0\n": {Check: "mac", OK: false, Value: "selinux permissive"},
		"":    {Check: "mac", OK: false, Value: "selinux disabled"},
	} {
		os.Remove(enforce)
		if body != "" {
			os.WriteFile(enforce, []byte(body), 0o644)
		}
		if got := p.MACCheck(); !reflect.DeepEqual(got, []postureCheck{want}) {
			t.Errorf("%q: %+v", body, got)
		}
	}
	if p.PublishedPorts() != nil || p.ContainerAdmins("/etc/group") != nil {
		t.Fatal("ports or admins")
	}
	if p.ContainerSocket() != "/run/podman/podman.sock" {
		t.Fatal("podman socket")
	}
}

// On an image system integrity must stop with one warning, not baseline
// every program in /usr/bin as unowned.
func TestFedoraAtomicSkipsIntegrity(t *testing.T) {
	fedoraAtomicFixture(t)
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: t.TempDir()}, platform: fedoraAtomicPlatform{}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { a.runIntegrity(ctx); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("runIntegrity kept running on fedoraatomic")
	}
	if len(a.queue) != 1 || a.queue[0].Type != "agent.warning" || a.queue[0].Data["collector"] != "integrity" ||
		!strings.Contains(a.queue[0].Data["error"].(string), "image") {
		t.Fatalf("events: %+v", a.queue)
	}
	if _, err := os.Stat(integrityStatePath(a.cfg.StateDir)); err == nil {
		t.Fatal("no integrity state may be written")
	}
	if _, ok := Platform(debianPlatform{}).(integrityUnsupported); ok {
		t.Fatal("debian checks integrity")
	}
}

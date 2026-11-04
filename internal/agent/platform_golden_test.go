package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/akquisio-dev/vigil/internal/dpkgver"
)

// Golden tests for everything that reads Debian or Ubuntu state (see
// docs/platform.md). They were written against the code before the platform
// layer existed and must stay unchanged while it moves behind the interface:
// same fixture in, same facts out.

// debianFixture builds a small dpkg/apt/boot tree and points sysRoot at it.
func debianFixture(t *testing.T) string {
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
	write("var/lib/dpkg/status", `Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.13-0ubuntu3.4

Package: libssl3t64
Status: install ok installed
Architecture: amd64
Source: openssl (3.0.13-0ubuntu3.5)
Version: 3.0.13-0ubuntu3.5

Package: coreutils
Status: install ok installed
Architecture: amd64
Version: 9.4-3ubuntu6

Package: gone
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0

Package: vigil-agent
Status: install ok installed
Architecture: amd64
Version: 0.35.0
`)
	write("var/lib/dpkg/info/coreutils.md5sums",
		"0123456789abcdef0123456789abcdef  usr/bin/ls\n"+
			"fedcba9876543210fedcba9876543210  usr/share/doc/coreutils/README\n"+
			"11111111111111111111111111111111  usr/bin/su\n")
	write("var/lib/dpkg/info/libssl3t64:amd64.md5sums",
		"22222222222222222222222222222222  usr/lib/x86_64-linux-gnu/libssl.so.3\n")
	write("var/lib/dpkg/info/login.md5sums",
		"33333333333333333333333333333333  usr/bin/su\n")
	write("var/lib/dpkg/diversions", "/usr/bin/su\n/usr/bin/su.distrib\ncoreutils\n")
	write("var/lib/dpkg/info/coreutils.list", "/.\n/usr\n/usr/bin\n/usr/bin/ls\n/bin/su\n")
	write("var/lib/dpkg/info/vigil-agent.list", "/usr/bin/vigil-agent\n")
	write("var/lib/dpkg/statoverride", "root crontab 2755 /usr/bin/crontab\n")
	write("etc/apt/apt.conf.d/20auto-upgrades",
		"APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")
	write("etc/apt/apt.conf.d/99off", "// APT::Periodic::Unattended-Upgrade \"0\";\n")
	write("boot/vmlinuz-6.8.0-45-generic", "")
	write("boot/vmlinuz-6.8.0-147-generic", "")
	write("boot/vmlinuz-6.8.0-9-generic", "")
	old := sysRoot
	sysRoot = root
	t.Cleanup(func() { sysRoot = old })
	return root
}

func TestGoldenSourcePackages(t *testing.T) {
	debianFixture(t)
	got := sourcePackages(dpkgPath("status"), func(a, b string) bool { return dpkgver.Compare(a, b) > 0 })
	want := []srcPkg{{"coreutils", "9.4-3ubuntu6"}, {"openssl", "3.0.13-0ubuntu3.5"}, {"vigil-agent", "0.35.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("source packages:\n got %v\nwant %v", got, want)
	}
}

func TestGoldenPackageFiles(t *testing.T) {
	debianFixture(t)
	got := packageFiles()
	// README is out of scope; /usr/bin/su of coreutils is diverted by
	// coreutils itself, so it stays, and login's entry is a duplicate.
	want := map[string]pkgEntry{
		canonical("/usr/bin/ls"):                           {pkg: "coreutils", ver: "9.4-3ubuntu6", md5: "0123456789abcdef0123456789abcdef"},
		canonical("/usr/bin/su"):                           {pkg: "coreutils", ver: "9.4-3ubuntu6", md5: "11111111111111111111111111111111"},
		canonical("/usr/lib/x86_64-linux-gnu/libssl.so.3"): {pkg: "libssl3t64", ver: "3.0.13-0ubuntu3.5", md5: "22222222222222222222222222222222"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("package files:\n got %v\nwant %v", got, want)
	}
	if v := dpkgVersions(); v["openssl"] != "3.0.13-0ubuntu3.4" || v["libssl3t64:amd64"] != "3.0.13-0ubuntu3.5" {
		t.Fatalf("versions: %v", v)
	}
	if d := dpkgDiversions(); d["/usr/bin/su"] != "coreutils" {
		t.Fatalf("diversions: %v", d)
	}
}

func TestGoldenDpkgBusy(t *testing.T) {
	root := debianFixture(t)
	if dpkgBusy() {
		t.Fatal("idle fixture reported busy")
	}
	os.MkdirAll(filepath.Join(root, "var/lib/dpkg/updates"), 0o755)
	os.WriteFile(filepath.Join(root, "var/lib/dpkg/updates/0001"), []byte("x"), 0o644)
	if !dpkgBusy() {
		t.Fatal("pending updates directory must count as busy")
	}
}

func TestGoldenOwners(t *testing.T) {
	root := debianFixture(t)
	info := lookupDpkg([]string{"/usr/bin/ls", "/usr/bin/su", "/usr/bin/crontab", "/opt/x"})
	if !info.ok {
		t.Fatal("lists present: ok must be true")
	}
	wantOwner := map[string]string{"/usr/bin/ls": "coreutils", "/usr/bin/su": "coreutils"}
	if !reflect.DeepEqual(info.owner, wantOwner) {
		t.Fatalf("owners: %v", info.owner)
	}
	fi, _ := os.Stat(filepath.Join(root, "var/lib/dpkg/info/coreutils.list"))
	if !info.installed["coreutils"].Equal(fi.ModTime()) || len(info.installed) != 1 {
		t.Fatalf("installed: %v", info.installed)
	}
	if !reflect.DeepEqual(info.override, map[string]bool{"/usr/bin/crontab": true}) {
		t.Fatalf("overrides: %v", info.override)
	}
	exe := filepath.Join(t.TempDir(), "vigil-agent")
	if dpkgOwner(exe) != "" {
		t.Fatal("a file outside the list has no owner")
	}
	if dpkgOwner("/usr/bin/vigil-agent") != "vigil-agent" && !symlinked("/usr/bin/vigil-agent") {
		t.Fatal("listed binary must be owned by the package")
	}
}

// symlinked reports whether p resolves elsewhere on this host, in which
// case dpkgOwner compares the resolved path and the fixture cannot match.
func symlinked(p string) bool {
	r, err := filepath.EvalSymlinks(p)
	return err == nil && r != p
}

func TestGoldenUpdateFacts(t *testing.T) {
	debianFixture(t)
	if !unattendedEnabled() {
		t.Fatal("unattended upgrades are on in the fixture")
	}
	if _, newest := kernelVersions(); newest != "6.8.0-147-generic" {
		t.Fatalf("newest kernel: %q", newest)
	}
	out := []byte("Listing...\n" +
		"openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]\n" +
		"vim/noble-updates 2:9.1.0016-1ubuntu7.4 amd64 [upgradable from: 2:9.1.0016-1ubuntu7.3]\n")
	want := []aptPending{{name: "openssl", security: true}, {name: "vim", security: false}}
	if got := parseAptUpgradable(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("apt: %v", got)
	}
}

func TestGoldenFirewallContainersInterfaces(t *testing.T) {
	nat := "*nat\n:DOCKER - [0:0]\n" +
		"-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.17.0.2:5432\n" +
		"-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.17.0.3:80\n" +
		"-A DOCKER -i docker0 -j RETURN\nCOMMIT\n"
	want := []Port{
		{Via: "docker", Proto: "tcp", Addr: "127.0.0.1", Scope: scopeOf([]byte{127, 0, 0, 1}), Port: 5432, Target: "172.17.0.2:5432"},
		{Via: "docker", Proto: "tcp", Addr: "0.0.0.0", Scope: "any", Port: 8080, Target: "172.17.0.3:80"},
	}
	if got := ParseDockerNAT(nat); !reflect.DeepEqual(got, want) {
		t.Fatalf("docker NAT:\n got %+v\nwant %+v", got, want)
	}
	ok, how := nftFilters([]byte("table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n }\n}\n"))
	if !ok || how == "" {
		t.Fatalf("nft with drop policy: %v %q", ok, how)
	}
	g := filepath.Join(t.TempDir(), "group")
	os.WriteFile(g, []byte("root:x:0:\ndocker:x:998:zoe,adam\n"), 0o644)
	if got := dockerGroup(g); !reflect.DeepEqual(got, []string{"adam", "zoe"}) {
		t.Fatalf("docker group: %v", got)
	}
	for name, skip := range map[string]bool{"lo": true, "docker0": true, "veth12": true, "br-1": true, "eth0": false, "ens3": false, "wg0": false} {
		if skipIface(name) != skip {
			t.Fatalf("skipIface(%q) = %v", name, !skip)
		}
	}
	if !vendoredDir("/opt/x/node_modules", "node_modules") || !vendoredDir("/usr/lib/ruby", "ruby") || vendoredDir("/srv/app", "app") {
		t.Fatal("vendored dirs")
	}
	if !underAny("/var/lib/dpkg/info", secretSkipPaths) {
		t.Fatal("dpkg data is skipped by the secret search")
	}
}

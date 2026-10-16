package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestParseAuthorizedKeys(t *testing.T) {
	data := []byte(`# comment
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl laptop
from="10.0.0.1,10.0.0.2",command="echo hi there" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl restricted key
garbage line
`)
	keys := ParseAuthorizedKeys(data)
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if keys[0].Comment != "laptop" || !strings.HasPrefix(keys[0].Fingerprint, "SHA256:") {
		t.Errorf("first key: %+v", keys[0])
	}
	if keys[1].Comment != "restricted key" || !strings.Contains(keys[1].Options, "command=") {
		t.Errorf("second key: %+v", keys[1])
	}
	if keys[0].Fingerprint != keys[1].Fingerprint {
		t.Error("same blob must give same fingerprint")
	}
}

func TestParseProcNetAddr(t *testing.T) {
	ip, port, err := parseProcNetAddr("0100007F:1F90")
	if err != nil || ip.String() != "127.0.0.1" || port != 8080 {
		t.Fatalf("got %v %d %v", ip, port, err)
	}
	ip, port, err = parseProcNetAddr("00000000000000000000000000000000:0016")
	if err != nil || ip.String() != "::" || port != 22 {
		t.Fatalf("got %v %d %v", ip, port, err)
	}
	ip, _, _ = parseProcNetAddr("00000000000000000000000001000000:0016")
	if ip.String() != "::1" {
		t.Fatalf("got %v", ip)
	}
}

func TestParseDockerNAT(t *testing.T) {
	dump := `*nat
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i br-1 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 172.18.0.2:80
-A DOCKER -d 127.0.0.1/32 ! -i br-2 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.19.0.3:5432
COMMIT`
	ports := ParseDockerNAT(dump)
	if len(ports) != 2 {
		t.Fatalf("want 2, got %d", len(ports))
	}
	if ports[0].Scope != "any" || ports[0].Port != 8080 || ports[0].Target != "172.18.0.2:80" {
		t.Errorf("exposed port: %+v", ports[0])
	}
	if ports[1].Scope != "loopback" || ports[1].Port != 5432 {
		t.Errorf("loopback port: %+v", ports[1])
	}
}

func TestSSHRegexes(t *testing.T) {
	m := reAccepted.FindStringSubmatch("Accepted publickey for root from 203.0.113.7 port 51234 ssh2: ED25519 SHA256:abcDEF123")
	if m == nil || m[1] != "publickey" || m[2] != "root" || m[3] != "203.0.113.7" || m[6] != "SHA256:abcDEF123" {
		t.Fatalf("accepted: %q", m)
	}
	if m := reAccepted.FindStringSubmatch("Accepted password for alice from 198.51.100.2 port 22 ssh2"); m == nil || m[1] != "password" {
		t.Fatalf("password: %q", m)
	}
	if m := reFailed.FindStringSubmatch("Failed password for invalid user admin from 198.51.100.9 port 4242 ssh2"); m == nil || m[2] != "admin" {
		t.Fatalf("failed: %q", m)
	}
	if m := reSudo.FindStringSubmatch("    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"); m == nil || m[1] != "alice" || m[5] != "/usr/bin/id" {
		t.Fatalf("sudo: %q", m)
	}
}

func testAgent(t *testing.T) (*Agent, string) {
	root := t.TempDir()
	a := &Agent{cfg: &Config{CanaryRoots: []string{root}, MaxQueue: 100}, state: &State{Canaries: map[string]*CanaryState{}}}
	return a, root
}

func TestCanaryPathRules(t *testing.T) {
	a, root := testAgent(t)
	bad := []string{
		"/etc/shadow-copy",
		root,
		root + "/../x.txt",
		root + "/.ssh/authorized_keys",
		root + "/.bashrc",
		root + "/cron.d/job",
		root + "/systemd/x.txt",
		root + "/backup.sh",
		"relative/path",
	}
	for _, p := range bad {
		if err := a.validateCanaryPath(p); err == nil {
			t.Errorf("%s: expected refusal", p)
		}
	}
	if err := a.validateCanaryPath(root + "/backup/old-credentials.txt"); err != nil {
		t.Errorf("valid path refused: %v", err)
	}
}

func TestCanaryNeverFollowsSymlinks(t *testing.T) {
	a, root := testAgent(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.placeCanary(proto.Canary{ID: "x", Type: "env", Path: root + "/link/secret.env"}); err == nil {
		t.Fatal("placing through a symlinked directory must fail")
	}
	if err := os.Symlink(filepath.Join(outside, "target"), filepath.Join(root, "file.env")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.placeCanary(proto.Canary{ID: "y", Type: "env", Path: root + "/file.env"}); err == nil {
		t.Fatal("placing onto a symlink must fail")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatal("something was written outside the canary root")
	}
}

func TestCanaryNeverOverwrites(t *testing.T) {
	a, root := testAgent(t)
	p := root + "/existing.txt"
	os.WriteFile(p, []byte("real data"), 0o600)
	if _, err := a.placeCanary(proto.Canary{ID: "x", Type: "credentials", Path: p}); err == nil {
		t.Fatal("existing file must not be overwritten")
	}
	if b, _ := os.ReadFile(p); string(b) != "real data" {
		t.Fatal("existing file was changed")
	}
}

func TestCanaryLifecycle(t *testing.T) {
	a, root := testAgent(t)
	for _, typ := range proto.CanaryTypes {
		p := root + "/deep/dir/" + typ
		cs, err := a.placeCanary(proto.Canary{ID: typ, Type: typ, Path: p})
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() == 0 {
			t.Fatalf("%s: bad file %v %v", typ, fi, err)
		}
		if err := removeCanary(cs); err != nil {
			t.Fatalf("%s remove: %v", typ, err)
		}
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s: still there", typ)
		}
	}
}

func TestRemoveRefusesReplacedFile(t *testing.T) {
	a, root := testAgent(t)
	p := root + "/c.txt"
	cs, err := a.placeCanary(proto.Canary{ID: "x", Type: "credentials", Path: p})
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(p)
	os.WriteFile(p, []byte("someone else's file"), 0o600)
	if err := removeCanary(cs); err == nil {
		t.Fatal("a replaced file must not be deleted")
	}
}

func TestSSHKeyCanaryIsValid(t *testing.T) {
	key, err := GenerateCanary("ssh-key", map[string]string{"comment": "backup@test"})
	if err != nil {
		t.Fatal(err)
	}
	bin, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	f := filepath.Join(t.TempDir(), "k")
	os.WriteFile(f, key, 0o600)
	out, err := exec.Command(bin, "-y", "-f", f).CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "ssh-ed25519 ") {
		t.Fatalf("ssh-keygen rejected the key: %s %v", out, err)
	}
}

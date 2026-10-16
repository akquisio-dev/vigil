package agent

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func results(a *Agent) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, e := range a.queue {
		if e.Type == "response.result" {
			out[e.Data["action_id"].(string)] = e.Data
		}
	}
	return out
}

func TestResponseGate(t *testing.T) {
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: t.TempDir()}, state: &State{}, flushNow: make(chan struct{}, 1)}
	future := time.Now().Add(time.Minute)
	acts := []proto.Action{{ID: "a1", Type: "kill_process", Params: map[string]string{"pid": "1"}, Expires: future}}
	a.runActions(acts)
	if r := results(a)["a1"]; r["ok"] != false || !strings.Contains(r["error"].(string), "not allowed") {
		t.Fatalf("disabled response must refuse: %v", r)
	}
	a.queue = nil
	a.runActions(acts)
	if len(a.queue) != 0 {
		t.Fatal("an action id runs at most once")
	}
	a.cfg.Response = &ResponseConfig{Enabled: true, Allow: []string{"remove_key"}}
	a.runActions([]proto.Action{
		{ID: "a2", Type: "kill_process", Params: map[string]string{"pid": "1"}, Expires: future},
		{ID: "a3", Type: "remove_key", Params: map[string]string{}, Expires: time.Now().Add(-time.Second)},
	})
	r := results(a)
	if r["a2"]["ok"] != false || !strings.Contains(r["a3"]["error"].(string), "expired") {
		t.Fatalf("allow list and expiry: %v", r)
	}
	if err := a.refuseBlock(nil); err == nil {
		t.Fatal("nil address")
	}
	a.cfg.Response.NeverBlock = []string{"10.90.0.0/24"}
	for _, ip := range []string{"127.0.0.1", "10.90.0.7", "fe80::1"} {
		if a.refuseBlock(parseIP(ip)) == nil {
			t.Errorf("%s must be refused", ip)
		}
	}
	if a.refuseBlock(parseIP("203.0.113.9")) != nil {
		t.Error("a public attacker address may be blocked")
	}
}

func TestRemoveKey(t *testing.T) {
	dir := t.TempDir()
	keyRoots = []string{dir + "/"}
	defer func() { keyRoots = []string{"/root/.ssh/", "/home/"} }()
	file := filepath.Join(dir, "authorized_keys")
	alice := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKLkE9EWuBOmcnrrMSp97JtGvd10Gz1RKtUSOklWlIe alice"
	bob := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7d1q4dRw1i6VYXjQ6v8vX1yB2m5bX4cK0dQ1y7mW2c bob"
	os.WriteFile(file, []byte("# keys\n"+alice+"\n"+bob+"\n"), 0o600)
	fp := ParseAuthorizedKeys([]byte(bob))[0].Fingerprint
	if _, err := removeAuthorizedKey(file, fp, dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if strings.Contains(string(b), "bob") || !strings.Contains(string(b), "alice") || !strings.HasPrefix(string(b), "# keys") {
		t.Fatalf("file now: %q", b)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "backups", "*"))
	if len(backups) != 1 {
		t.Fatal("a backup is written first")
	}
	alicefp := ParseAuthorizedKeys([]byte(alice))[0].Fingerprint
	if _, err := removeAuthorizedKey(file, alicefp, dir); err == nil || !strings.Contains(err.Error(), "last key") {
		t.Fatalf("the last key must stay: %v", err)
	}
	if _, err := removeAuthorizedKey(filepath.Join(dir, "../etc/passwd"), fp, dir); err == nil {
		t.Fatal("only authorized_keys files")
	}
}

func TestKillProcess(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	exe, _ := os.Readlink("/proc/" + itoa(cmd.Process.Pid) + "/exe")
	if _, err := killProcess(cmd.Process.Pid, "/usr/bin/other"); err == nil {
		t.Fatal("a pid running another program must not be killed")
	}
	if _, err := killProcess(cmd.Process.Pid, exe); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	if _, err := killSession(cmd.Process.Pid, "root"); err == nil {
		t.Fatal("only SSH sessions")
	}
}

func itoa(n int) string       { return strconv.Itoa(n) }
func parseIP(s string) net.IP { return net.ParseIP(s) }

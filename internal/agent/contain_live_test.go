package agent

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// TestContainmentLive isolates and locks for real. Run it only inside a
// throwaway container with its own network and /etc:
//
//	docker run --rm --cap-add NET_ADMIN -e VIGIL_CONTAIN_TEST=1 -v $PWD/agent.test:/t ubuntu:24.04 /t -test.run ContainmentLive -test.v
func TestContainmentLive(t *testing.T) {
	if os.Getenv("VIGIL_CONTAIN_TEST") != "1" {
		t.Skip("set VIGIL_CONTAIN_TEST=1, inside a container only")
	}
	reach := func() bool {
		return exec.Command("curl", "-s", "-m", "4", "-o", "/dev/null", "http://1.1.1.1").Run() == nil
	}
	if !reach() {
		t.Fatal("no network to begin with")
	}
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: t.TempDir(), Server: "http://192.0.2.10:8471",
		Response: &ResponseConfig{Enabled: true}}, state: &State{}, flushNow: make(chan struct{}, 1)}
	if _, err := a.doAction(proto.Action{ID: "i0", Type: "isolate_host"}); err == nil || !strings.Contains(err.Error(), "nobody could reach") {
		t.Fatalf("isolation without an allowed address: %v", err)
	}
	a.cfg.Response.IsolateAllow = []string{"203.0.113.0/24"}
	detail, err := a.doAction(proto.Action{ID: "i1", Type: "isolate_host", Params: map[string]string{"minutes": "5"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(detail)
	if reach() {
		t.Fatal("still reaches the internet while isolated")
	}
	out, _ := exec.Command("nft", "list", "table", "inet", nftIsolateTable).CombinedOutput()
	if !strings.Contains(string(out), "192.0.2.10") || !strings.Contains(string(out), "203.0.113.0/24") {
		t.Fatalf("ruleset: %s", out)
	}
	// Removed by hand (or a reboot): the next scan puts it back.
	exec.Command("nft", "delete", "table", "inet", nftIsolateTable).Run()
	a.checkContainment()
	if reach() {
		t.Fatal("isolation not restored")
	}
	// Time is up: released without the server.
	a.state.Contain.IsolatedUntil = time.Now().Add(-time.Second)
	a.checkContainment()
	if !reach() {
		t.Fatal("not released after the end time")
	}

	// Accounts
	if err := exec.Command("useradd", "-m", "-s", "/bin/bash", "vigiltest").Run(); err != nil {
		t.Fatal(err)
	}
	exec.Command("usermod", "-e", "2030-01-01", "vigiltest").Run()
	exec.Command("bash", "-c", "echo vigiltest:Pw-for-the-test-1 | chpasswd").Run()
	shadowOf := func() []string {
		sh, _ := os.ReadFile("/etc/shadow")
		for _, l := range strings.Split(string(sh), "\n") {
			if strings.HasPrefix(l, "vigiltest:") {
				return strings.Split(l, ":")
			}
		}
		return nil
	}
	before := shadowOf()
	if _, err := a.doAction(proto.Action{ID: "l0", Type: "lock_user", Params: map[string]string{"user": "root"}}); err == nil {
		t.Fatal("root locked")
	}
	a.cfg.Response.NeverLock = []string{"vigiltest"}
	if _, err := a.doAction(proto.Action{ID: "l1", Type: "lock_user", Params: map[string]string{"user": "vigiltest"}}); err == nil {
		t.Fatal("never_lock ignored")
	}
	a.cfg.Response.NeverLock = nil
	if d, err := a.doAction(proto.Action{ID: "l2", Type: "lock_user", Params: map[string]string{"user": "vigiltest", "minutes": "60"}}); err != nil {
		t.Fatal(err)
	} else {
		t.Log(d)
	}
	sh, _ := os.ReadFile("/etc/shadow")
	line := ""
	for _, l := range strings.Split(string(sh), "\n") {
		if strings.HasPrefix(l, "vigiltest:") {
			line = l
		}
	}
	f := strings.Split(line, ":")
	if !strings.HasPrefix(f[1], "!") || f[7] != "1" {
		t.Fatalf("not locked: %s", line)
	}
	if exec.Command("su", "-s", "/bin/true", "vigiltest").Run() == nil {
		t.Fatal("expired account still usable with su")
	}
	a.state.Contain.Locked["vigiltest"] = LockInfo{Until: time.Now().Add(-time.Second), PrevExpire: a.state.Contain.Locked["vigiltest"].PrevExpire}
	a.checkContainment()
	after := shadowOf()
	if after[1] != before[1] || after[7] != before[7] || strings.HasPrefix(after[1], "!") {
		t.Fatalf("not restored: %v -> %v", before, after)
	}
	if len(a.state.Contain.Locked) != 0 {
		t.Fatal("lock still recorded")
	}
	evs := eventTypes(a)
	if len(evs["response.state"]) == 0 {
		t.Fatal("no state reports")
	}
}

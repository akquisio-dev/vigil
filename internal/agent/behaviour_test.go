package agent

import (
	"os"
	"testing"
	"time"
)

func TestSessionCommands(t *testing.T) {
	a := &Agent{cfg: &Config{MaxQueue: 1000}, flushNow: make(chan struct{}, 1)}
	now := time.Now()
	a.sessions.login(os.Getpid(), "joey", "203.0.113.9", now)
	// A shell command whose parent chain reaches the sshd process (here:
	// this test process stands in for sshd).
	e := &ExecInfo{PID: 999999, PPID: os.Getpid(), UID: 0, Exe: "/usr/bin/vim", Cmdline: "vim /etc/sudoers", ParentComm: "bash", LoginUID: 1000, SessionID: 42}
	a.sessionExec(e)
	ev := eventTypes(a)["session.exec"]
	if len(ev) != 1 || ev[0]["user"] != "joey" || ev[0]["sshd_pid"] != os.Getpid() || ev[0]["cmdline"] != "vim /etc/sudoers" {
		t.Fatalf("session exec: %v", ev)
	}
	// Inside tmux the parent chain is gone, the audit session id remains.
	tm := &ExecInfo{PID: 999998, PPID: 1, Exe: "/usr/bin/ls", ParentComm: "bash", LoginUID: 1000, SessionID: 42}
	a.sessionExec(tm)
	if len(eventTypes(a)["session.exec"]) != 1 {
		t.Fatal("tmux command not tied to its session")
	}
	// Not interactive (a cron job, a service), or no login session: nothing.
	for _, x := range []*ExecInfo{
		{PID: 5, PPID: os.Getpid(), Exe: "/usr/bin/x", ParentComm: "cron", LoginUID: 1000, SessionID: 42},
		{PID: 6, PPID: os.Getpid(), Exe: "/usr/bin/x", ParentComm: "bash", LoginUID: auditUnset, SessionID: auditUnset},
		{PID: 7, PPID: 1, Exe: "/usr/bin/x", ParentComm: "bash", LoginUID: 1000, SessionID: 77},
	} {
		a.sessionExec(x)
	}
	if n := len(eventTypes(a)["session.exec"]); n != 0 {
		t.Fatalf("%d unrelated commands reported", n)
	}
	// Secrets on the command line are removed.
	a.sessionExec(&ExecInfo{PID: 8, PPID: os.Getpid(), Exe: "/usr/bin/mysql", Cmdline: "mysql -u root -phunter66", ParentComm: "bash", LoginUID: 0, SessionID: 42})
	if ev := eventTypes(a)["session.exec"]; ev[0]["cmdline"] != "mysql -u root -p[removed]" {
		t.Fatalf("redaction: %v", ev[0]["cmdline"])
	}
	// The hourly cap, and the count of what was left out.
	s := a.sessions.byPID[os.Getpid()]
	s.sent = sessionCmdsPerHour
	a.sessionExec(e)
	a.sessionExec(e)
	s.hour = now.Add(-2 * time.Hour)
	a.sessionExec(e)
	evs := eventTypes(a)
	if len(evs["session.exec"]) != 1 || len(evs["session.dropped"]) != 1 || evs["session.dropped"][0]["count"] != 2 {
		t.Fatalf("cap: %v", evs)
	}
	if got := a.sessions.logout(os.Getpid(), now); got == nil || got.End.IsZero() {
		t.Fatal("logout")
	}
}

func TestRarity(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfg: &Config{MaxQueue: 1000, StateDir: dir}, flushNow: make(chan struct{}, 1)}
	a.rare = loadRare(dir)
	learn := func(e *ExecInfo) { a.rareExec(e) }
	// Learning: nothing is reported.
	learn(&ExecInfo{Exe: "/usr/sbin/nginx", Comm: "nginx", ParentComm: "systemd"})
	learn(&ExecInfo{Exe: "/usr/bin/php", ParentComm: "nginx"})
	if n := len(eventTypes(a)); n != 0 {
		t.Fatalf("reported while learning: %d", n)
	}
	a.rare.Since = time.Now().Add(-8 * 24 * time.Hour)
	learn(&ExecInfo{Exe: "/usr/sbin/nginx", ParentComm: "systemd"}) // known
	learn(&ExecInfo{Exe: "/usr/bin/php", ParentComm: "nginx"})      // known pair
	learn(&ExecInfo{Exe: "/bin/sh", ParentComm: "nginx"})           // new pair, sh known? no: new exe too
	learn(&ExecInfo{Exe: "/tmp/x", ParentComm: "bash"})             // temp dirs are someone else's job
	learn(&ExecInfo{Exe: "/opt/x/bin", ParentComm: "bash", MntNS: "mnt:[1]"})
	time.Sleep(300 * time.Millisecond) // the package check runs in the background
	ev := eventTypes(a)
	if len(ev["process.rare_child"]) != 1 || ev["process.rare_child"][0]["parent_comm"] != "nginx" {
		t.Fatalf("rare child: %v", ev)
	}
	// /bin/sh is packaged on any test machine with dpkg; elsewhere it is reported.
	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil && len(ev["process.rare"]) != 0 && hostMntNS != "mnt:[1]" {
		for _, d := range ev["process.rare"] {
			if d["exe"] == "/bin/sh" {
				t.Fatalf("packaged program reported: %v", d)
			}
		}
	}
	a.rare.save(dir)
	if back := loadRare(dir); !back.Exes["/usr/sbin/nginx"] || !back.Pairs["nginx|sh"] {
		t.Fatalf("state: %+v", back)
	}
}

func TestVolumeDelta(t *testing.T) {
	prev := map[string]ifaceBytes{"eth0": {100, 1000}, "wg0": {10, 10}}
	cur := map[string]ifaceBytes{"eth0": {300, 500}, "wg0": {20, 30}, "eth1": {5, 5}}
	rx, tx := volumeDelta(prev, cur)
	if rx != 210 || tx != 520 {
		t.Fatalf("rx %d tx %d", rx, tx)
	}
	if !skipIface("veth12ab") || !skipIface("lo") || skipIface("eth0") || skipIface("wg0") {
		t.Fatal("skipIface")
	}
	if m := readNetDev("/proc/net/dev"); m == nil {
		t.Fatal("no /proc/net/dev")
	}
}

func TestRarityIgnoresBuildOutput(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: dir, RareIgnore: []string{"/srv/builds/"}}, flushNow: make(chan struct{}, 1)}
	a.rare = loadRare(dir)
	a.rare.Since = time.Now().Add(-30 * 24 * time.Hour)
	for _, p := range []string{"/root/.cache/go-tmp/go-build123/b001/x.test", "/home/u/app/target/debug/app", "/srv/builds/42/tool"} {
		a.rareExec(&ExecInfo{Exe: p, ParentComm: "bash"})
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(eventTypes(a)); n != 0 || len(a.rare.Exes) != 0 {
		t.Fatalf("build output learned or reported: %d events, %d exes", n, len(a.rare.Exes))
	}
}

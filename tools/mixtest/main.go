// Command mixtest runs an old release and the current build against each
// other, the way an update meets them in the field: agents are updated
// first, then the server, and a broken server is rolled back to the old
// binary on the data the new one wrote.
//
//	sudo mixtest -old DIR -new DIR [-selftest]
//
// Each DIR holds vigil-server and vigil-agent. Agents must run as root.
// The servers listen on loopback only. Run it in a network namespace
// (unshare -n) on a machine that has an agent of its own.
//
// What a cross version break looks like, and what is checked in every
// phase: the agent stays online without enrolling again, reports the
// expected version, takes a signed configuration (a canary appears on
// disk), and none of the alerts for rejected configs, forged or dropped
// batches or a broken event chain is open. Self update is not covered:
// the current build has no signed release yet.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

// badRules are the alerts that mean old and new do not understand each
// other. agent.stopped and agent.restarted are expected here.
var badRules = []string{"agent.config_rejected", "agent.forged", "agent.dropped", "chain.broken", "agent.silent", "selftest.failed"}

type side struct {
	dir     string
	version string
}

func (s side) bin(cmd string) string { return filepath.Join(s.dir, cmd) }

var (
	work     string
	selftest bool
	lastTOTP int64
)

func main() {
	oldDir := flag.String("old", "", "directory with the old vigil-server and vigil-agent")
	newDir := flag.String("new", "", "directory with the new vigil-server and vigil-agent")
	flag.StringVar(&work, "work", "", "working directory (default: a new temporary one, removed on success)")
	flag.BoolVar(&selftest, "selftest", false, "also run an agent self test in every phase (leaves traces in /etc/cron.d, /tmp and the journal)")
	flag.Parse()
	if *oldDir == "" || *newDir == "" {
		flag.Usage()
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		fatal("mixtest must run as root (the agents need it)")
	}
	old, cur := side{dir: *oldDir}, side{dir: *newDir}
	for _, s := range []*side{&old, &cur} {
		s.version = versionOf(s.bin("vigil-server"))
		if v := versionOf(s.bin("vigil-agent")); v != s.version {
			fatal("%s: vigil-server is %s, vigil-agent is %s", s.dir, s.version, v)
		}
	}
	if old.version == cur.version {
		fatal("old and new are both %s; nothing to compare", old.version)
	}
	keep := work != ""
	if !keep {
		var err error
		if work, err = os.MkdirTemp("", "vigil-mixtest-"); err != nil {
			fatal("%v", err)
		}
	}
	fmt.Printf("mixtest: old %s, new %s, in %s\n", old.version, cur.version, work)

	err := run(old, cur)
	stopAll()
	if err != nil {
		dumpLogs()
		fmt.Fprintln(os.Stderr, "FAIL", err)
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			// Annotations can be read without signing in, job logs cannot.
			fmt.Printf("::error title=mixtest %s against %s::%s\n", old.version, cur.version, strings.ReplaceAll(err.Error(), "\n", " "))
		}
		os.Exit(1)
	}
	if !keep {
		os.RemoveAll(work)
	}
	fmt.Println("mixtest: all phases passed")
}

func run(old, cur side) error {
	srv := newServer()

	phase("1  old server %s, new agent %s enrolls", old.version, cur.version)
	if err := srv.start(old); err != nil {
		return err
	}
	a1 := newAgent("a1")
	if err := a1.enroll(srv, cur); err != nil {
		return err
	}
	if err := a1.start(cur); err != nil {
		return err
	}
	if err := check(srv, a1, cur); err != nil {
		return err
	}

	phase("2  new server %s on the old data, new agent goes on without enrolling", cur.version)
	if err := srv.restart(cur); err != nil {
		return err
	}
	if err := check(srv, a1, cur); err != nil {
		return err
	}

	phase("3  old agent %s enrolls with the new server", old.version)
	a2 := newAgent("a2")
	if err := a2.enroll(srv, old); err != nil {
		return err
	}
	if err := a2.start(old); err != nil {
		return err
	}
	if err := check(srv, a2, old); err != nil {
		return err
	}

	phase("4  old agent replaced by the new one on its own state")
	if err := a2.restart(cur); err != nil {
		return err
	}
	if err := check(srv, a2, cur); err != nil {
		return err
	}

	phase("5  both versions accept the event chain the new server wrote")
	srv.stop()
	for _, s := range []side{old, cur} {
		out, err := exec.Command(s.bin("vigil-server"), "verify", "-config", srv.cfg).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s verify: %v: %s", s.version, err, out)
		}
		fmt.Printf("     %s verify: %s", s.version, out)
	}

	phase("6  rollback: old server %s on the data of the new one", old.version)
	if err := srv.start(old); err != nil {
		return err
	}
	for _, a := range []*agent{a1, a2} {
		if err := check(srv, a, cur); err != nil {
			return err
		}
	}
	return nil
}

func phase(format string, args ...any) {
	fmt.Printf("phase "+format+"\n", args...)
}

// check runs every per phase assertion for one agent.
func check(s *server, a *agent, want side) error {
	since := time.Now().UTC().Add(-time.Second)
	if err := s.waitOnline(a, want.version, since); err != nil {
		return err
	}
	if err := s.pushCanary(a); err != nil {
		return err
	}
	if err := s.waitStarted(a, want.version); err != nil {
		return err
	}
	if selftest {
		if err := s.selfTest(a); err != nil {
			return err
		}
	}
	if err := s.noBadAlerts(); err != nil {
		return err
	}
	fmt.Printf("     ok  %s (%s) online, config taken\n", a.name, want.version)
	return nil
}

func versionOf(bin string) string {
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		fatal("%s version: %v", bin, err)
	}
	return strings.TrimSpace(string(out))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "mixtest: "+format+"\n", args...)
	stopAll()
	os.Exit(1)
}

// ---- processes ----

var running []*exec.Cmd

func spawn(logPath, bin string, args ...string) (*exec.Cmd, error) {
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(f, "---- %s %s\n", filepath.Base(bin), strings.Join(args, " "))
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	running = append(running, cmd)
	go func() { cmd.Wait(); f.Close() }()
	return cmd, nil
}

func stop(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	cmd.Process.Signal(syscall.SIGTERM)
	for i := 0; i < 100 && cmd.ProcessState == nil; i++ {
		if cmd.Process.Signal(syscall.Signal(0)) != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cmd.Process.Kill()
	running = slices.DeleteFunc(running, func(c *exec.Cmd) bool { return c == cmd })
}

func stopAll() {
	for len(running) > 0 {
		stop(running[len(running)-1])
	}
}

func dumpLogs() {
	logs, _ := filepath.Glob(filepath.Join(work, "*.log"))
	for _, l := range logs {
		b, _ := os.ReadFile(l)
		if len(b) > 6000 {
			b = b[len(b)-6000:]
		}
		fmt.Fprintf(os.Stderr, "==== %s\n%s\n", filepath.Base(l), b)
	}
}

// ---- server ----

type server struct {
	cfg, data, base, secret string
	cmd                     *exec.Cmd
	client                  *http.Client
	cookie, csrf            string
}

func newServer() *server {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("%v", err)
	}
	addr := l.Addr().String()
	l.Close()
	s := &server{cfg: filepath.Join(work, "server.json"), data: filepath.Join(work, "server"), base: "http://" + addr, client: &http.Client{Timeout: 10 * time.Second}}
	cfg := map[string]any{"listen": addr, "data_dir": s.data, "cookie_secure": false, "language": "en", "notifiers": []any{}, "deadman_seconds": 30}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(s.cfg, b, 0o600); err != nil {
		fatal("%v", err)
	}
	return s
}

func (s *server) start(v side) error {
	if s.secret == "" {
		// The first server creates the user; later ones find it in the data.
		cmd := exec.Command(v.bin("vigil-server"), "user", "add", "-config", s.cfg, "-role", "admin", "mixtest")
		cmd.Stdin = strings.NewReader("mixtest-password-1234\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("user add: %v: %s", err, out)
		}
		m := regexp.MustCompile(`secret: ([A-Z2-7]+)`).FindSubmatch(out)
		if m == nil {
			return fmt.Errorf("user add printed no TOTP secret:\n%s", out)
		}
		s.secret = string(m[1])
	}
	cmd, err := spawn(filepath.Join(work, "server.log"), v.bin("vigil-server"), "run", "-config", s.cfg)
	if err != nil {
		return err
	}
	s.cmd = cmd
	deadline := time.Now().Add(20 * time.Second)
	for {
		res, err := s.client.Get(s.base + "/api/ui/me")
		if err == nil {
			res.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("server %s did not come up: %v", v.version, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return s.login()
}

func (s *server) stop() { stop(s.cmd); s.cmd = nil }

func (s *server) restart(v side) error {
	s.stop()
	return s.start(v)
}

// login waits for a TOTP window that was not used yet, since a code is
// accepted only once.
func (s *server) login() error {
	for time.Now().Unix()/30 <= lastTOTP {
		time.Sleep(time.Second)
	}
	n := time.Now().Unix() / 30
	lastTOTP = n
	s.cookie, s.csrf = "", ""
	var me struct {
		CSRF string `json:"csrf"`
	}
	hdr, err := s.call("POST", "/api/ui/login", map[string]string{"user": "mixtest", "password": "mixtest-password-1234", "code": totp(s.secret, n)}, &me)
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	var parts []string
	for _, c := range hdr.Values("Set-Cookie") {
		parts = append(parts, strings.SplitN(c, ";", 2)[0])
	}
	s.cookie, s.csrf = strings.Join(parts, "; "), me.CSRF
	return nil
}

func (s *server) call(method, path string, body, out any) (http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.csrf != "" {
		req.Header.Set("X-CSRF", s.csrf)
	}
	if s.cookie != "" {
		req.Header.Set("Cookie", s.cookie)
	}
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, res.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return nil, fmt.Errorf("%s %s: %v", method, path, err)
		}
	}
	return res.Header, nil
}

type agentInfo struct {
	ID         string    `json:"id"`
	Version    string    `json:"version"`
	Status     string    `json:"status"`
	LastSeen   time.Time `json:"last_seen"`
	ConfigSync bool      `json:"config_sync"`
}

func (s *server) agentInfo(id string) (agentInfo, error) {
	// Newer servers wrap the agent in {"agent": ...}.
	var raw map[string]json.RawMessage
	if _, err := s.call("GET", "/api/ui/agents/"+id, nil, &raw); err != nil {
		return agentInfo{}, err
	}
	b, err := json.Marshal(raw)
	if inner, ok := raw["agent"]; ok {
		b = inner
	}
	var a agentInfo
	if err == nil {
		err = json.Unmarshal(b, &a)
	}
	return a, err
}

func waitFor(what string, d time.Duration, f func() (bool, error)) error {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		ok, err := f()
		if ok {
			return nil
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	if last != nil {
		return fmt.Errorf("%s: timed out: %w", what, last)
	}
	return fmt.Errorf("%s: timed out", what)
}

func (s *server) waitOnline(a *agent, version string, since time.Time) error {
	var seen agentInfo
	err := waitFor(a.name+" online as "+version, 60*time.Second, func() (bool, error) {
		info, err := s.agentInfo(a.id)
		seen = info
		return err == nil && info.Status == "online" && info.Version == version && info.LastSeen.After(since), err
	})
	if err != nil {
		return fmt.Errorf("%w (last: %+v)", err, seen)
	}
	return nil
}

// pushCanary sends a configuration with one more canary through the signed
// config path and waits for the file and the acknowledgement.
func (s *server) pushCanary(a *agent) error {
	a.canaries++
	path := filepath.Join(a.canaryRoot, fmt.Sprintf("c%d", a.canaries), ".env")
	if _, err := s.call("POST", "/api/ui/canaries", map[string]any{"agent_id": a.id, "type": "env", "path": path}, nil); err != nil {
		return err
	}
	return waitFor(a.name+" takes the config with canary "+path, 60*time.Second, func() (bool, error) {
		if _, err := os.Lstat(path); err != nil {
			return false, err
		}
		info, err := s.agentInfo(a.id)
		if err == nil && !info.ConfigSync {
			err = errors.New("config_sync is false")
		}
		return err == nil, err
	})
}

func (s *server) waitStarted(a *agent, version string) error {
	return waitFor(a.name+" agent.started with "+version, 30*time.Second, func() (bool, error) {
		var recs []struct {
			Event struct {
				Data map[string]any `json:"data"`
			} `json:"event"`
		}
		if _, err := s.call("GET", "/api/ui/events?type=agent.started&limit=50&agent="+a.id, nil, &recs); err != nil {
			return false, err
		}
		for _, r := range recs {
			if r.Event.Data["version"] == version {
				return true, nil
			}
		}
		return false, fmt.Errorf("%d agent.started events, none with %s", len(recs), version)
	})
}

func (s *server) selfTest(a *agent) error {
	if _, err := s.call("POST", "/api/ui/agents/"+a.id+"/selftest", map[string]any{}, nil); err != nil {
		return err
	}
	var last string
	err := waitFor(a.name+" self test", 4*time.Minute, func() (bool, error) {
		var tests []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
			Steps  []struct {
				Step, Status, Detail string
			} `json:"steps"`
		}
		if _, err := s.call("GET", "/api/ui/selftests?agent="+a.id, nil, &tests); err != nil || len(tests) == 0 {
			return false, err
		}
		b, _ := json.Marshal(tests[0])
		last = string(b)
		switch tests[0].Status {
		case "passed":
			return true, nil
		case "pending", "running":
			return false, nil
		}
		return false, errors.New("finished as " + tests[0].Status)
	})
	if err != nil {
		return fmt.Errorf("%w: %s", err, last)
	}
	return nil
}

func (s *server) noBadAlerts() error {
	var alerts []struct {
		Rule, Title string
	}
	if _, err := s.call("GET", "/api/ui/alerts?status=open", nil, &alerts); err != nil {
		return err
	}
	for _, al := range alerts {
		if slices.Contains(badRules, al.Rule) {
			return fmt.Errorf("open alert %s: %s", al.Rule, al.Title)
		}
	}
	return nil
}

func totp(secret string, n int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(strings.ToUpper(secret), "="))
	if err != nil {
		fatal("TOTP secret: %v", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(n))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	o := h[len(h)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(h[o:])&0x7fffffff)%1000000)
}

// ---- agent ----

type agent struct {
	name, cfg, canaryRoot, id string
	canaries                  int
	cmd                       *exec.Cmd
}

func newAgent(name string) *agent {
	return &agent{name: name, cfg: filepath.Join(work, name+".json"), canaryRoot: filepath.Join(work, name+"-canaries")}
}

func (a *agent) enroll(s *server, v side) error {
	off := false
	cfg := map[string]any{
		"server": s.base, "state_dir": filepath.Join(work, a.name+"-state"),
		"interval_seconds": 2, "scan_seconds": 30, "canary_roots": []string{a.canaryRoot},
		"watch_files": []string{a.cfg},
		"ssh":         off, "ports": off, "docker": off, "processes": off, "kernel": off, "suid": off,
		"integrity": off, "bpf": off, "updates": off, "outbound": off, "posture": off, "secrets": off,
		"packages": off, "apps": off, "forensics": off, "sessions": off, "rarity": off, "yara": off, "volume": off,
		"selftest": selftest,
	}
	if selftest {
		// The self test needs the built-in watch list (cron) and the
		// process and ssh collectors.
		delete(cfg, "watch_files")
		cfg["processes"], cfg["ssh"] = true, true
	}
	if err := os.MkdirAll(a.canaryRoot, 0o755); err != nil {
		return err
	}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(a.cfg, b, 0o600); err != nil {
		return err
	}
	var tok struct {
		Token string `json:"token"`
	}
	if _, err := s.call("POST", "/api/ui/tokens", map[string]any{}, &tok); err != nil {
		return err
	}
	out, err := exec.Command(v.bin("vigil-agent"), "enroll", "-config", a.cfg, "-token", tok.Token).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s enroll: %v: %s", a.name, err, out)
	}
	m := regexp.MustCompile(`enrolled as (\S+)`).FindSubmatch(out)
	if m == nil {
		return fmt.Errorf("%s enroll printed no agent id: %s", a.name, out)
	}
	a.id = string(m[1])
	return nil
}

func (a *agent) start(v side) error {
	cmd, err := spawn(filepath.Join(work, a.name+".log"), v.bin("vigil-agent"), "run", "-config", a.cfg)
	a.cmd = cmd
	return err
}

func (a *agent) restart(v side) error {
	stop(a.cmd)
	return a.start(v)
}

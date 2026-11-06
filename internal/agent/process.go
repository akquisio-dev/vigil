package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// ExecInfo is what the agent learns about a program start from /proc.
type ExecInfo struct {
	PID, PPID   int
	UID         int
	Exe         string // " (deleted)" stripped, see Deleted
	Deleted     bool
	Preload     string // LD_PRELOAD from the environment
	Comm        string
	Cmdline     string
	Cwd         string
	ParentExe   string
	ParentComm  string
	StdioSocket bool   // stdin or stdout is a network socket
	LoginUID    uint32 // audit login uid, auditUnset outside login sessions
	SessionID   uint32 // audit session id
	MntNS       string // mount namespace, to tell containers apart
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true, "fish": true, "csh": true, "tcsh": true}

// isInterpreter matches python3.12, perl5.38 and the like.
func isInterpreter(base string) bool {
	for _, p := range []string{"python", "perl", "ruby", "php", "lua", "node"} {
		if strings.HasPrefix(base, p) && !strings.HasPrefix(base, "php-fpm") {
			return true
		}
	}
	return false
}

// Services that never start a shell in normal operation. Application
// runtimes such as node, java or python are left out on purpose: they start
// shells all the time (child_process.exec, build tools), and listing them
// would bury real findings.
var serviceParents = map[string]bool{
	"nginx": true, "apache2": true, "httpd": true, "lighttpd": true, "caddy": true,
	"mysqld": true, "mariadbd": true, "postgres": true, "redis-server": true, "mongod": true, "memcached": true,
}

var tmpDirs = []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/"}

// cmdSignals are matched against the command line. The names end up in the
// event and are what the server's rules look for.
var cmdSignals = []struct {
	name string
	re   *regexp.Regexp
}{
	{"reverse_shell", regexp.MustCompile(`/dev/(tcp|udp)/[^ /]+/[0-9]+|\bn(c|cat|etcat)\b[^|;]*\s-[a-z]*[ec]\b|\bsocat\b[^|;]*\b(exec|system):|\bpty\.spawn\(|socket\.socket\([^)]*\).*\bconnect\(|\bperl\b.*-e.*\bsocket\(|\bmkfifo\b.*\b(nc|ncat|sh)\b`)},
	{"download_exec", regexp.MustCompile(`\b(curl|wget|fetch)\b[^;|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^;]*(&&|;)\s*chmod\s+\+?[0-7]*x?\s|\bchmod\s+\+?[0-7]*x?\s+/(tmp|dev/shm|var/tmp)/`)},
	{"decode_exec", regexp.MustCompile(`\bbase64\s+(-d|--decode)\b[^;]*\|\s*(ba|z|da)?sh\b|\becho\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64`)},
	{"miner", regexp.MustCompile(`(?i)\bstratum\+(tcp|ssl|tls)://|--donate-level|\b(xmrig|xmr-stak|minerd|cpuminer|kdevtmpfsi|kinsing|nanominer|t-rex|lolminer|phoenixminer)\b|--cpu-max-threads-hint|--randomx`)},
}

// ownBootc tells the agent's own `bootc status --json` (platform
// fedoraatomic). bootc re-executes a copy of itself from /tmp/.tmpXXXXXX in a
// private mount namespace; seen on Fedora 44 with every status call. Only a
// direct child of this agent with exactly that command line is spared.
func (e *ExecInfo) ownBootc() bool {
	return e.PPID == os.Getpid() && e.Cmdline == "bootc status --json"
}

// bootc runs from such a copy for every command, whoever starts it (on Nyra
// the packages provider and the login status as well). Such a start is
// spared only when the running file is byte for byte the installed bootc:
// same name pattern, a bootc command line, and the same SHA-256 as
// bootcBinary. If the process is gone before it is hashed, it is reported.
var (
	bootcBinary  = "/usr/bin/bootc"
	bootcTmpName = regexp.MustCompile(`^/tmp/\.tmp[A-Za-z0-9]{6}$`)
	// procExeSHA hashes the running program; replaced in tests.
	procExeSHA = func(pid int) string {
		_, sha, err := hashFile("/proc/" + strconv.Itoa(pid) + "/exe")
		if err != nil {
			return ""
		}
		return sha
	}
	bootcSum struct {
		sync.Mutex
		size  int64
		mtime time.Time
		sha   string
	}
)

// installedBootcSHA is the hash of bootcBinary, recomputed when it changes.
func installedBootcSHA() string {
	st, err := os.Stat(bootcBinary)
	if err != nil {
		return ""
	}
	bootcSum.Lock()
	defer bootcSum.Unlock()
	if bootcSum.sha != "" && bootcSum.size == st.Size() && bootcSum.mtime.Equal(st.ModTime()) {
		return bootcSum.sha
	}
	_, sha, err := hashFile(bootcBinary)
	if err != nil {
		return ""
	}
	bootcSum.size, bootcSum.mtime, bootcSum.sha = st.Size(), st.ModTime(), sha
	return sha
}

func (e *ExecInfo) bootcCopy() bool {
	if e.PID <= 0 || !bootcTmpName.MatchString(e.Exe) {
		return false
	}
	if e.Cmdline != "bootc" && !strings.HasPrefix(e.Cmdline, "bootc ") {
		return false
	}
	want := installedBootcSHA()
	return want != "" && procExeSHA(e.PID) == want
}

// signals lists why a program start is worth reporting. An empty result
// means the start is not reported, which keeps busy hosts quiet.
func (e *ExecInfo) signals() []string {
	var out []string
	base := filepath.Base(e.Exe)
	// bootc deletes its copy right after starting it, so a spared copy is
	// spared as a deleted program as well.
	spared := false
	for _, d := range tmpDirs {
		if strings.HasPrefix(e.Exe, d) {
			if e.ownBootc() || e.bootcCopy() {
				spared = true
			} else {
				out = append(out, "tmp_exe")
			}
			break
		}
	}
	switch {
	case strings.HasPrefix(e.Exe, "/memfd:"):
		// A program run from an anonymous memory file never touched the
		// disk. runc (up to 1.1) re-executes itself this way on every
		// container start; that one name is expected.
		if !(strings.HasPrefix(e.Exe, "/memfd:runc_cloned:") && strings.HasPrefix(e.Comm, "runc")) {
			out = append(out, "memfd_exe")
		}
	case e.Deleted && !spared:
		out = append(out, "deleted_exe")
	}
	if e.Preload != "" {
		out = append(out, "ld_preload")
	}
	isShell := shells[base] || shells[e.Comm]
	if isShell && e.StdioSocket {
		out = append(out, "shell_socket")
	}
	if (isShell || isInterpreter(base)) && (serviceParents[e.ParentComm] || strings.HasPrefix(e.ParentComm, "php-fpm")) {
		out = append(out, "service_shell")
	}
	for _, s := range cmdSignals {
		if s.re.MatchString(e.Cmdline) {
			out = append(out, "cmd_"+s.name)
		}
	}
	return out
}

func clipCmd(s string) string {
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}

// procLimiter caps process events per minute; a fork bomb or a busy build
// must not flood the queue. Drops are reported in the next minute.
type procLimiter struct {
	window  time.Time
	sent    int
	dropped int
}

const procEventsPerMinute = 60

func (l *procLimiter) allow(now time.Time) (ok bool, dropped int) {
	if now.Sub(l.window) >= time.Minute {
		dropped, l.window, l.sent, l.dropped = l.dropped, now, 0, 0
	}
	if l.sent >= procEventsPerMinute {
		l.dropped++
		return false, dropped
	}
	l.sent++
	return true, dropped
}

func (a *Agent) reportExec(e *ExecInfo) {
	sig := e.signals()
	if len(sig) == 0 {
		return
	}
	a.mu.Lock()
	ok, dropped := a.procLimit.allow(time.Now())
	a.mu.Unlock()
	if dropped > 0 {
		a.emit(proto.NewEvent("process.rate_limited", map[string]any{"dropped": dropped}))
	}
	if !ok {
		return
	}
	if e.Preload != "" {
		// Children inherit LD_PRELOAD; one report per program and library
		// is enough until the agent restarts.
		k := e.Exe + "|" + e.Preload
		a.mu.Lock()
		if a.preloadSeen == nil {
			a.preloadSeen = map[string]bool{}
		}
		dup := a.preloadSeen[k]
		if !dup && len(a.preloadSeen) < 1000 {
			a.preloadSeen[k] = true
		}
		a.mu.Unlock()
		if dup && len(sig) == 1 {
			return
		}
	}
	d := map[string]any{"pid": e.PID, "ppid": e.PPID, "uid": e.UID, "exe": e.Exe, "comm": e.Comm, "cmdline": clipCmd(redactCmd(e.Cmdline)),
		"cwd": e.Cwd, "parent_exe": e.ParentExe, "parent_comm": e.ParentComm, "signals": sig}
	if e.Preload != "" {
		d["ld_preload"] = clipCmd(e.Preload)
	}
	tagCgroup(d, e)
	// The program is opened right away, hashed and scanned in the
	// background; the report follows with the hash.
	scan := a.scanProcess(e.PID, e.Exe, "exec")
	cid := a.pidContainer(e.PID)
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		if sha := scan(); sha != "" {
			d["exe_sha256"] = sha
		}
		a.tagContainerID(d, cid)
		a.emit(proto.NewEvent("process.exec", d))
		a.flushSoon()
	}()
	for _, x := range sig {
		if snapSignals[x] {
			go a.snapshot(e.PID, "process.exec:"+x, "", "")
			break
		}
	}
}

// tagCgroup adds where a reported program runs: its cgroup and systemd unit
// from /proc/<pid>/cgroup, read while it still runs, and mnt_ns_private when
// its mount namespace is not the host's. A unit with PrivateTmp= runs in a
// namespace of its own whose /tmp is /tmp/systemd-private-*-<unit>-*/tmp on
// the host, yet /proc shows its programs as /tmp/...: mnt_ns_private with a
// unit tells that case from a program in the host's /tmp.
func tagCgroup(d map[string]any, e *ExecInfo) {
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(e.PID) + "/cgroup"); err == nil {
		if cg := cgroupPath(string(b)); cg != "" {
			d["cgroup"] = cg
			if u := cgroupUnit(cg); u != "" {
				d["unit"] = u
			}
		}
	}
	if e.MntNS != "" && hostMntNS != "" && e.MntNS != hostMntNS {
		d["mnt_ns_private"] = true
	}
}

// cgroupPath is the cgroup v2 path ("0::/system.slice/x.service"), else the
// path of the first v1 hierarchy that has one.
func cgroupPath(content string) string {
	first := ""
	for _, l := range strings.Split(content, "\n") {
		parts := strings.SplitN(l, ":", 3)
		if len(parts) != 3 || parts[2] == "" {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return parts[2]
		}
		if first == "" && parts[2] != "/" {
			first = parts[2]
		}
	}
	return first
}

// cgroupUnit is the innermost systemd unit in a cgroup path:
// "/system.slice/bootc-fetch-apply-updates.service" -> its service,
// "/user.slice/user-1000.slice/session-3.scope" -> "session-3.scope". A
// sub-cgroup a unit made itself (Delegate=) belongs to that unit.
func cgroupUnit(path string) string {
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		for _, suf := range []string{".service", ".scope", ".socket", ".mount", ".swap"} {
			if strings.HasSuffix(parts[i], suf) && len(parts[i]) > len(suf) {
				return parts[i]
			}
		}
	}
	return ""
}

package agent

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// ExecInfo is what the agent learns about a program start from /proc.
type ExecInfo struct {
	PID, PPID   int
	UID         int
	Exe         string // " (deleted)" stripped, see Deleted
	Deleted     bool
	Comm        string
	Cmdline     string
	Cwd         string
	ParentExe   string
	ParentComm  string
	StdioSocket bool // stdin or stdout is a network socket
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

// signals lists why a program start is worth reporting. An empty result
// means the start is not reported, which keeps busy hosts quiet.
func (e *ExecInfo) signals() []string {
	var out []string
	base := filepath.Base(e.Exe)
	for _, d := range tmpDirs {
		if strings.HasPrefix(e.Exe, d) {
			out = append(out, "tmp_exe")
			break
		}
	}
	if e.Deleted {
		out = append(out, "deleted_exe")
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
	d := map[string]any{"pid": e.PID, "ppid": e.PPID, "uid": e.UID, "exe": e.Exe, "comm": e.Comm, "cmdline": clipCmd(e.Cmdline),
		"cwd": e.Cwd, "parent_exe": e.ParentExe, "parent_comm": e.ParentComm, "signals": sig}
	a.emit(proto.NewEvent("process.exec", d))
	a.flushSoon()
}

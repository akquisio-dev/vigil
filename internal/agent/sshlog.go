package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

var (
	reAccepted   = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+))?`)
	reFailed     = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(\S*) from (\S+) port`)
	reInvalid    = regexp.MustCompile(`^Invalid user (\S*) from (\S+)`)
	reDisconnect = regexp.MustCompile(`^Disconnected from user (\S+) (\S+) port (\d+)`)
	reSudo       = regexp.MustCompile(`^\s*(\S+) : .*?(?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; COMMAND=(.*)$`)
)

// failures aggregates failed SSH attempts per source so a brute-force wave
// becomes one event per interval instead of thousands.
type failures struct {
	count int
	users map[string]bool
}

func (a *Agent) runSSH(ctx context.Context) {
	journalctl, err := exec.LookPath("journalctl")
	if err != nil {
		a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "ssh", "error": "journalctl not found"}))
		return
	}
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.followJournal(ctx, journalctl)
		if ctx.Err() != nil {
			return
		}
		log.Printf("ssh: journal reader stopped: %v", err)
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < time.Minute {
			backoff *= 2
		}
	}
}

func (a *Agent) followJournal(ctx context.Context, bin string) error {
	cmd := exec.CommandContext(ctx, bin, "-f", "-n", "0", "-o", "json", "--no-pager",
		"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sudo")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var entry map[string]any
		if json.Unmarshal(sc.Bytes(), &entry) != nil {
			continue
		}
		msg, _ := entry["MESSAGE"].(string)
		ident, _ := entry["SYSLOG_IDENTIFIER"].(string)
		ts := time.Now().UTC()
		if us, ok := entry["__REALTIME_TIMESTAMP"].(string); ok {
			if n, err := strconv.ParseInt(us, 10, 64); err == nil {
				ts = time.UnixMicro(n).UTC()
			}
		}
		pid, _ := entry["_PID"].(string)
		if ident == "sudo" {
			a.handleSudo(msg, ts)
		} else {
			a.handleSSH(msg, pid, ts)
		}
	}
	return cmd.Wait()
}

func (a *Agent) handleSSH(msg, pid string, ts time.Time) {
	if m := reAccepted.FindStringSubmatch(msg); m != nil {
		d := map[string]any{"method": m[1], "user": m[2], "ip": m[3], "port": atoi(m[4]), "sshd_pid": atoi(pid)}
		if m[6] != "" {
			d["key_type"] = m[5]
			d["fingerprint"] = m[6]
			a.mu.Lock()
			ref, ok := a.keyNames[m[6]]
			a.mu.Unlock()
			if ok {
				d["key_file"] = ref.File
				d["key_comment"] = ref.Comment
			}
		}
		a.emit(proto.Event{Type: "ssh.login", TS: ts, Data: d})
		return
	}
	if m := reDisconnect.FindStringSubmatch(msg); m != nil {
		a.emit(proto.Event{Type: "ssh.logout", TS: ts, Data: map[string]any{"user": m[1], "ip": m[2], "port": atoi(m[3]), "sshd_pid": atoi(pid)}})
		return
	}
	var user, ip string
	if m := reFailed.FindStringSubmatch(msg); m != nil {
		user, ip = m[2], m[3]
	} else if m := reInvalid.FindStringSubmatch(msg); m != nil {
		user, ip = m[1], m[2]
	} else {
		return
	}
	a.mu.Lock()
	f := a.sshFails[ip]
	if f == nil {
		f = &failures{users: map[string]bool{}}
		a.sshFails[ip] = f
	}
	f.count++
	if len(f.users) < 10 {
		f.users[user] = true
	}
	a.mu.Unlock()
}

// flushSSHFailures is called right before each batch is sent.
func (a *Agent) flushSSHFailures() {
	a.mu.Lock()
	fails := a.sshFails
	a.sshFails = map[string]*failures{}
	a.mu.Unlock()
	for ip, f := range fails {
		users := make([]string, 0, len(f.users))
		for u := range f.users {
			users = append(users, u)
		}
		a.emit(proto.NewEvent("ssh.failed", map[string]any{"ip": ip, "count": f.count, "users": users}))
	}
}

func (a *Agent) handleSudo(msg string, ts time.Time) {
	m := reSudo.FindStringSubmatch(msg)
	if m == nil {
		return
	}
	cmd := strings.TrimSpace(m[5])
	if len(cmd) > 500 {
		cmd = cmd[:500]
	}
	a.emit(proto.Event{Type: "sudo.command", TS: ts, Data: map[string]any{"user": m[1], "tty": m[2], "cwd": m[3], "as": m[4], "command": cmd}})
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

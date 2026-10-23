package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

var (
	reAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)(?: ssh2)?(?:: (\S+) (\S+))?`)
	reFailed   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S*) from (\S+) port (\d+)`)
	reInvalid  = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	// With password logins off, attempts on existing accounts leave only
	// this line when the client gives up (no "Failed" line at all).
	reAuthClosed = regexp.MustCompile(`^(?:Connection closed by|Disconnected from|Connection reset by) authenticating user (\S+) (\S+) port (\d+)`)
	reDisconnect = regexp.MustCompile(`^Disconnected from user (\S+) (\S+) port (\d+)`)
	reSudo       = regexp.MustCompile(`^\s*(\S+) : .*?(?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ; COMMAND=(.*)$`)
)

var trustedComm = map[string]bool{"sshd": true, "sshd-session": true, "sudo": true}

// trustedExe are the programs that write under these identifiers without
// being root: sudo logs with the uid of the user who ran it, and sshd's
// unprivileged process for a session with that user's. _EXE is read by
// journald from /proc; a copy of the program elsewhere does not match.
var trustedExe = map[string]bool{"/usr/bin/sudo": true, "/usr/sbin/sshd": true,
	"/usr/lib/openssh/sshd-session": true, "/usr/libexec/openssh/sshd-session": true}

func clip(s string) string {
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

// failures aggregates failed SSH attempts per source so a brute-force wave
// becomes one event per interval instead of thousands.
type failures struct {
	count int
	// users counts the attempts per tried user, for the first ten users of
	// an address; attempts for further users only count in count.
	users map[string]int
	// existing are the tried users the server has an account for (sshd
	// says "invalid user" for the others).
	existing map[string]bool
}

// Connection states for counting attempts: each connection counts once
// for its first line, and every further failed password once more.
const (
	connInvalid = 1 // "Invalid user" seen, its first password try is the same attempt
	connCounted = 2
)

func (a *Agent) runSSH(ctx context.Context) {
	journalctl, err := exec.LookPath("journalctl")
	if err != nil {
		a.collectorFailed("ssh", "journalctl not found")
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
	args := []string{"-f", "-o", "json", "--no-pager"}
	a.mu.Lock()
	cursor := a.cursor
	a.mu.Unlock()
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else {
		args = append(args, "-n", "0")
	}
	args = append(args, "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sudo")
	cmd := exec.CommandContext(ctx, bin, args...)
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
		if c, ok := entry["__CURSOR"].(string); ok {
			a.mu.Lock()
			a.cursor = c
			a.mu.Unlock()
		}
		msg, _ := entry["MESSAGE"].(string)
		ident, _ := entry["SYSLOG_IDENTIFIER"].(string)
		// SYSLOG_IDENTIFIER is chosen by the sender (`logger -t sshd` works
		// for anyone). _COMM and _UID are set by journald and cannot be faked.
		comm, _ := entry["_COMM"].(string)
		uid, _ := entry["_UID"].(string)
		exe, _ := entry["_EXE"].(string)
		if use, spoofed := journalEntry(uid, comm, exe, ident); !use {
			if spoofed {
				a.emit(proto.NewEvent("log.spoofed", map[string]any{"identifier": ident, "comm": clip(comm), "uid": uid, "message": clip(msg)}))
			}
			continue
		}
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
		a.sessions.login(atoi(pid), m[2], m[3], ts)
		return
	}
	if m := reDisconnect.FindStringSubmatch(msg); m != nil {
		a.emit(proto.Event{Type: "ssh.logout", TS: ts, Data: map[string]any{"user": m[1], "ip": m[2], "port": atoi(m[3]), "sshd_pid": atoi(pid)}})
		if s := a.sessions.logout(atoi(pid), ts); s != nil && s.drops > 0 {
			a.emit(proto.NewEvent("session.dropped", map[string]any{"sshd_pid": s.PID, "user": s.User, "count": s.drops}))
		}
		return
	}
	var user, ip, port string
	var exists bool
	kind := 0
	if m := reFailed.FindStringSubmatch(msg); m != nil {
		user, ip, port, exists, kind = m[3], m[4], m[5], m[2] == "", 1
	} else if m := reInvalid.FindStringSubmatch(msg); m != nil {
		user, ip, port, kind = m[1], m[2], m[3], 2
	} else if m := reAuthClosed.FindStringSubmatch(msg); m != nil {
		user, ip, port, exists, kind = m[1], m[2], m[3], true, 3
	} else {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	conn := ip + " " + port
	st := a.sshConns[conn]
	count := false
	switch kind {
	case 1: // Failed password: every try counts, but the one "Invalid user" announced
		count = st != connInvalid
		st = connCounted
	case 2: // Invalid user: the connection's first line
		count = st == 0
		if st == 0 {
			st = connInvalid
		}
	case 3: // the client gave up on an existing account
		count = st == 0
		st = connCounted
	}
	if port != "" && len(a.sshConns) < 20000 {
		a.sshConns[conn] = st
	}
	f := a.sshFails[ip]
	if f == nil {
		f = &failures{users: map[string]int{}, existing: map[string]bool{}}
		a.sshFails[ip] = f
	}
	if count {
		f.count++
	}
	if _, seen := f.users[user]; len(f.users) < 10 || seen {
		if count {
			f.users[user]++
		} else {
			f.users[user] += 0
		}
		if exists {
			f.existing[user] = true
		}
	}
}

// flushSSHFailures is called right before each batch is sent.
func (a *Agent) flushSSHFailures() {
	a.mu.Lock()
	fails := a.sshFails
	a.sshFails = map[string]*failures{}
	a.sshConns = map[string]int{}
	a.mu.Unlock()
	for ip, f := range fails {
		if f.count == 0 {
			continue
		}
		users := make([]string, 0, len(f.users))
		perUser := map[string]any{}
		for u, n := range f.users {
			users = append(users, u)
			if n > 0 {
				perUser[u] = n
			}
		}
		sort.Strings(users)
		d := map[string]any{"ip": ip, "count": f.count, "users": users, "user_counts": perUser}
		if len(f.existing) > 0 {
			ex := make([]string, 0, len(f.existing))
			for u := range f.existing {
				ex = append(ex, u)
			}
			sort.Strings(ex)
			d["existing_users"] = ex
		}
		a.emit(proto.NewEvent("ssh.failed", d))
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

// spoofedLog tells an entry under a trusted identifier that its sender
// did not write. _UID comes with the message (socket credentials); _COMM is
// read from /proc and is missing when the sender exited first, as an sshd
// for a connection closed before authentication often has. Only root can
// send as uid 0, and root could as well name its program sshd, so uid 0
// with an unknown name counts as genuine.
// journalEntry decides on one entry: use it for logins, or drop it, and
// whether dropping it is worth a log.spoofed. sudo run by a user and sshd's
// process for a user's session write without being root; they are genuine,
// but no login is read from them.
func journalEntry(uid, comm, exe, ident string) (use, spoofed bool) {
	if uid != "0" && trustedExe[exe] {
		return false, false
	}
	if spoofedLog(uid, comm) {
		return false, ident != "" && trustedComm[ident]
	}
	return true, false
}

func spoofedLog(uid, comm string) bool {
	return uid != "0" || (comm != "" && !trustedComm[comm])
}

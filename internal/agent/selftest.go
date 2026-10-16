package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// The self test leaves three traces, each marked with the test id, that the
// real collectors must report. They are fixed here: the server only sends
// an id, so a compromised server can make the agent write a comment into a
// cron directory and start `sleep 1` from /tmp, nothing else.

var selfTestID = regexp.MustCompile(`^[0-9a-f]{16}$`)

// selfTestCronDirs are tried in order. The packaged unit runs the agent
// with ProtectSystem=full, which makes /etc read-only, so the crontab spool
// (watched, writable, ignored by cron for unknown users) comes first.
var selfTestCronDirs = []string{"/var/spool/cron/crontabs", "/etc/cron.d"}

const (
	selfTestPrefix = "vigil-selftest-"
	selfTestBody   = "# vigil self test %s. Harmless, removed again within seconds.\n"
)

func selfTestSkip(step, why string) map[string]any {
	return map[string]any{"step": step, "skipped": why}
}

// runSelfTest runs on the main loop, like a scan, so the file step can scan
// in between. It returns quickly: every step is a few syscalls.
func (a *Agent) runSelfTest(t *proto.SelfTest) {
	if t == nil || !selfTestID.MatchString(t.ID) {
		return
	}
	key := "selftest:" + t.ID
	if a.state.ActionsDone == nil {
		a.state.ActionsDone = map[string]time.Time{}
	}
	if _, done := a.state.ActionsDone[key]; done {
		return
	}
	a.state.ActionsDone[key] = time.Now()
	ev := func(typ string, d map[string]any) {
		d["id"] = t.ID
		a.emit(proto.NewEvent(typ, d))
	}
	switch {
	case time.Now().After(t.Expires):
		ev("selftest.done", map[string]any{"error": "expired before it reached the host"})
		return
	case !on(a.cfg.SelfTest):
		ev("selftest.done", map[string]any{"error": "selftest is off in agent.json"})
		return
	}
	ev("selftest.started", map[string]any{})
	marker := selfTestPrefix + t.ID

	if why := a.selfTestFile(marker, t.ID); why != "" {
		ev("selftest.step", selfTestSkip("file", why))
	}
	if !on(a.cfg.Processes) {
		ev("selftest.step", selfTestSkip("process", "process collector is off"))
	} else if down := a.collectorDown("process"); down != "" {
		ev("selftest.step", map[string]any{"step": "process", "error": "process collector is not running: " + down})
	} else if why := selfTestExec(marker); why != "" {
		ev("selftest.step", selfTestSkip("process", why))
	}
	if !on(a.cfg.SSH) {
		ev("selftest.step", selfTestSkip("journal", "ssh collector is off"))
	} else if down := a.collectorDown("ssh"); down != "" {
		ev("selftest.step", map[string]any{"step": "journal", "error": "ssh collector is not running: " + down})
	} else if why := selfTestJournal(marker); why != "" {
		ev("selftest.step", selfTestSkip("journal", why))
	}
	ev("selftest.done", map[string]any{})
	a.flushSoon()
}

// selfTestFile creates a comment-only file in a watched cron directory,
// scans, removes it and scans again. It never follows a link and never
// replaces a file.
func (a *Agent) selfTestFile(marker, id string) string {
	var f *os.File
	var path string
	why := "no watched cron directory (" + strings.Join(selfTestCronDirs, ", ") + ")"
	for _, dir := range selfTestCronDirs {
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() || !a.watched(filepath.Join(dir, marker)) {
			continue
		}
		path = filepath.Join(dir, marker)
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
		if err == nil {
			break
		}
		why = "cannot create a file in " + dir + ": " + err.Error()
	}
	if f == nil {
		return why
	}
	_, err := fmt.Fprintf(f, selfTestBody, id)
	f.Close()
	if err == nil {
		a.scanFiles()
	}
	os.Remove(path)
	a.scanFiles()
	if err != nil {
		return "cannot write the test file: " + err.Error()
	}
	return ""
}

// selfTestExec copies `sleep` into a fresh directory below /tmp and runs it.
func selfTestExec(marker string) string {
	src, err := exec.LookPath("sleep")
	if err != nil {
		return "sleep not found"
	}
	dir, err := os.MkdirTemp("/tmp", marker+"-")
	if err != nil {
		return "cannot create a directory in /tmp: " + err.Error()
	}
	defer os.RemoveAll(dir)
	in, err := os.Open(src)
	if err != nil {
		return err.Error()
	}
	defer in.Close()
	bin := filepath.Join(dir, "sleep")
	out, err := os.OpenFile(bin, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o700)
	if err != nil {
		return err.Error()
	}
	_, err = io.Copy(out, in)
	out.Close()
	if err != nil {
		return err.Error()
	}
	// It runs for a second: the collector reads exe and command line from
	// /proc after the kernel reports the start, and a program that has
	// already exited leaves nothing there to read.
	cmd := exec.Command(bin, "1")
	cmd.Dir = "/"
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return "/tmp is mounted noexec"
		}
		return "cannot start the test program: " + err.Error()
	}
	return ""
}

// selfTestJournal writes an auth.info line tagged sshd to the syslog socket.
// journald records the agent as its sender, which the SSH collector reports
// as log.spoofed.
func selfTestJournal(marker string) string {
	c, err := net.DialTimeout("unixgram", "/dev/log", 2*time.Second)
	if err != nil {
		return "no syslog socket: " + err.Error()
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("<38>sshd: " + marker + " (vigil self test, not a real login)")); err != nil {
		return err.Error()
	}
	return ""
}

func (a *Agent) watched(path string) bool {
	for _, p := range a.watchGlobs() {
		if ok, _ := filepath.Match(p, path); ok {
			return true
		}
	}
	return false
}

func (a *Agent) watchGlobs() []string {
	globs := a.cfg.WatchFiles
	if len(globs) == 0 {
		globs = DefaultWatch
	}
	return append(append([]string{}, globs...), a.cfg.ExtraWatch...)
}

// cleanSelfTests removes traces left by a test that was interrupted (agent
// killed between create and remove). Only files with exactly the content
// the agent writes, and directories holding only its copy of `sleep`.
func cleanSelfTests() {
	var files []string
	for _, dir := range selfTestCronDirs {
		m, _ := filepath.Glob(filepath.Join(dir, selfTestPrefix+"*"))
		files = append(files, m...)
	}
	for _, p := range files {
		id := strings.TrimPrefix(filepath.Base(p), selfTestPrefix)
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || !selfTestID.MatchString(id) {
			continue
		}
		if b, err := os.ReadFile(p); err == nil && string(b) == fmt.Sprintf(selfTestBody, id) {
			os.Remove(p)
		}
	}
	dirs, _ := filepath.Glob(filepath.Join("/tmp", selfTestPrefix+"*"))
	for _, d := range dirs {
		fi, err := os.Lstat(d)
		if err != nil || !fi.IsDir() {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			continue
		}
		entries, err := os.ReadDir(d)
		if err != nil || len(entries) > 1 || len(entries) == 1 && entries[0].Name() != "sleep" {
			continue
		}
		os.RemoveAll(d)
	}
}

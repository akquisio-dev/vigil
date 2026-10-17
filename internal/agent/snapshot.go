package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Evidence snapshots: what is lost when a process exits or the host is
// rebooted, captured at the moment of detection. For its own strongest
// signals (reverse shell, miner, program from memory, LD_PRELOAD, a
// service starting a shell, an opened canary) the agent takes the snapshot
// right away, while the process still runs; the server can ask for one for
// any other alert. A snapshot only reads: process list, the suspect
// process in detail (program hash, parents, open files, libraries,
// sockets, names of its environment variables), network sockets, logged-in
// users, kernel modules and the last journal lines. Copying the program
// into quarantine is a separate opt-in. Snapshots travel in the signed
// agent batches and end up in the server's hash chain like every event.

const (
	snapMaxPerHour   = 12
	snapMaxBytes     = 400 << 10
	snapMaxProcs     = 600
	snapMaxConns     = 300
	quarantineMax    = 64 << 20
	quarantineTotal  = 512 << 20
	quarantineMaxAge = 30 * 24 * time.Hour
)

// Signals that take a snapshot on the spot.
var snapSignals = map[string]bool{"shell_socket": true, "cmd_reverse_shell": true, "cmd_miner": true, "memfd_exe": true,
	"deleted_exe": true, "service_shell": true, "ld_preload": true, "cmd_download_exec": true}

type snapLimiter struct {
	mu    sync.Mutex
	times []time.Time
	pids  map[int]time.Time
}

// allow limits snapshots to snapMaxPerHour and one per process in ten
// minutes, so a burst of shells cannot fill the queue or the disk.
func (l *snapLimiter) allow(pid int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := l.times[:0]
	for _, t := range l.times {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	l.times = keep
	if len(l.times) >= snapMaxPerHour {
		return false
	}
	if l.pids == nil {
		l.pids = map[int]time.Time{}
	}
	if pid > 0 {
		if t, ok := l.pids[pid]; ok && now.Sub(t) < 10*time.Minute {
			return false
		}
		l.pids[pid] = now
		if len(l.pids) > 500 {
			for p, t := range l.pids {
				if now.Sub(t) > 10*time.Minute {
					delete(l.pids, p)
				}
			}
		}
	}
	l.times = append(l.times, now)
	return true
}

type snapProc struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	UID     int    `json:"uid"`
	Comm    string `json:"comm"`
	Exe     string `json:"exe,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
}

type snapConn struct {
	Proto  string `json:"proto"`
	State  string `json:"state"`
	Local  string `json:"local"`
	Remote string `json:"remote,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Comm   string `json:"comm,omitempty"`
}

func readProc(pid int) (snapProc, bool) {
	dir := "/proc/" + strconv.Itoa(pid)
	p := snapProc{PID: pid}
	b, err := os.ReadFile(dir + "/status")
	if err != nil {
		return p, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(line, ":")
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		switch k {
		case "Name":
			p.Comm = f[0]
		case "PPid":
			p.PPID, _ = strconv.Atoi(f[0])
		case "Uid":
			p.UID, _ = strconv.Atoi(f[0])
		}
	}
	p.Exe, _ = os.Readlink(dir + "/exe")
	if c, err := os.ReadFile(dir + "/cmdline"); err == nil {
		p.Cmdline = clipLen(strings.TrimSpace(string(bytes.ReplaceAll(c, []byte{0}, []byte{' '}))), 300)
	}
	return p, true
}

func clipLen(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func listProcs() []snapProc {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	var out []snapProc
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil {
			continue
		}
		if p, ok := readProc(pid); ok {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

var tcpStates = map[string]string{"01": "established", "02": "syn_sent", "03": "syn_recv", "0A": "listen", "06": "time_wait", "08": "close_wait"}

// socketInodes maps socket inodes to the process holding them.
func socketInodes() map[string]snapProc {
	out := map[string]snapProc{}
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		fds, err := os.ReadDir(d + "/fd")
		if err != nil {
			continue
		}
		pid, _ := strconv.Atoi(filepath.Base(d))
		var comm string
		for _, fd := range fds {
			link, err := os.Readlink(d + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if comm == "" {
				c, _ := os.ReadFile(d + "/comm")
				comm = strings.TrimSpace(string(c))
			}
			out[link[8:len(link)-1]] = snapProc{PID: pid, Comm: comm}
		}
	}
	return out
}

func listConns(owners map[string]snapProc) []snapConn {
	var out []snapConn
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		fh, err := os.Open("/proc/net/" + f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan()
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 10 {
				continue
			}
			lip, lport, err1 := parseProcNetAddr(fl[1])
			rip, rport, err2 := parseProcNetAddr(fl[2])
			if err1 != nil || err2 != nil {
				continue
			}
			state := tcpStates[fl[3]]
			if strings.HasPrefix(f, "udp") {
				state = "udp"
			}
			if state == "" || state == "time_wait" {
				continue
			}
			c := snapConn{Proto: strings.TrimSuffix(f, "6"), State: state, Local: net.JoinHostPort(lip.String(), strconv.Itoa(lport))}
			if !rip.IsUnspecified() {
				c.Remote = net.JoinHostPort(rip.String(), strconv.Itoa(rport))
			}
			if o, ok := owners[fl[9]]; ok {
				c.PID, c.Comm = o.PID, o.Comm
			}
			out = append(out, c)
		}
		fh.Close()
	}
	// Established first: they are what an investigation looks at.
	sort.SliceStable(out, func(i, j int) bool { return out[i].State == "established" && out[j].State != "established" })
	return out
}

// utmpSessions reads who is logged in from /run/utmp (glibc layout, 384
// bytes per entry on 64-bit Linux).
func utmpSessions() []map[string]any {
	b, err := os.ReadFile("/run/utmp")
	if err != nil {
		return nil
	}
	cstr := func(x []byte) string {
		if i := bytes.IndexByte(x, 0); i >= 0 {
			x = x[:i]
		}
		return string(x)
	}
	var out []map[string]any
	for off := 0; off+384 <= len(b) && len(out) < 100; off += 384 {
		e := b[off : off+384]
		if binary.LittleEndian.Uint16(e[0:]) != 7 { // USER_PROCESS
			continue
		}
		pid := int32(binary.LittleEndian.Uint32(e[4:]))
		sec := int32(binary.LittleEndian.Uint32(e[340:]))
		out = append(out, map[string]any{"user": cstr(e[44:76]), "tty": cstr(e[8:40]), "host": cstr(e[76:332]), "pid": pid,
			"since": time.Unix(int64(sec), 0).UTC()})
	}
	return out
}

func moduleNames() []string {
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			out = append(out, f[0])
		}
	}
	return out
}

func journalTail(n int) []string {
	jc, err := exec.LookPath("journalctl")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, jc, "-n", strconv.Itoa(n), "-o", "short-iso", "--no-pager", "-q")
	cmd.Env = []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SYSTEMD_COLORS=0"}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			lines = append(lines, clipLen(redactLine("journal", l), 300))
		}
	}
	return lines
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// targetDetail describes the suspect process. The environment is reduced
// to variable names (values hold secrets), LD_PRELOAD excepted.
func targetDetail(pid int) map[string]any {
	dir := "/proc/" + strconv.Itoa(pid)
	p, ok := readProc(pid)
	if !ok {
		return map[string]any{"pid": pid, "gone": true}
	}
	t := map[string]any{"pid": p.PID, "ppid": p.PPID, "uid": p.UID, "comm": p.Comm, "exe": p.Exe, "cmdline": p.Cmdline}
	if cwd, err := os.Readlink(dir + "/cwd"); err == nil {
		t["cwd"] = cwd
	}
	if st, err := os.Stat(dir); err == nil {
		t["started"] = st.ModTime().UTC()
	}
	// Hash the program through /proc, which works for deleted files and
	// memfd programs too.
	if f, err := os.Open(dir + "/exe"); err == nil {
		h := sha256.New()
		if n, err := io.Copy(h, io.LimitReader(f, quarantineMax)); err == nil {
			t["exe_sha256"] = hex.EncodeToString(h.Sum(nil))
			t["exe_size"] = n
		}
		f.Close()
	}
	var anc []map[string]any
	for cur, i := p.PPID, 0; cur > 0 && i < 12; i++ {
		pp, ok := readProc(cur)
		if !ok {
			break
		}
		anc = append(anc, map[string]any{"pid": pp.PID, "comm": pp.Comm, "exe": pp.Exe, "uid": pp.UID, "cmdline": clipLen(pp.Cmdline, 160)})
		cur = pp.PPID
	}
	t["ancestry"] = anc
	if fds, err := os.ReadDir(dir + "/fd"); err == nil {
		var files []string
		for _, fd := range fds {
			if l, err := os.Readlink(dir + "/fd/" + fd.Name()); err == nil && len(files) < 64 {
				files = append(files, fd.Name()+" "+l)
			}
		}
		t["fds"] = files
	}
	if b, err := os.ReadFile(dir + "/maps"); err == nil {
		seen := map[string]bool{}
		var libs []string
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 6 || !strings.HasPrefix(f[5], "/") || seen[f[5]] {
				continue
			}
			seen[f[5]] = true
			if len(libs) < 64 {
				libs = append(libs, strings.Join(f[5:], " "))
			}
		}
		t["maps"] = libs
	}
	if f, err := os.Open(dir + "/environ"); err == nil {
		buf := make([]byte, 64<<10)
		n, _ := io.ReadFull(f, buf)
		f.Close()
		var names []string
		for _, kv := range bytes.Split(buf[:n], []byte{0}) {
			k, v, _ := strings.Cut(string(kv), "=")
			if k == "LD_PRELOAD" {
				t["ld_preload"] = clipLen(v, 300)
			}
			if envName.MatchString(k) && len(names) < 100 {
				names = append(names, k)
			}
		}
		t["env_names"] = names
	}
	return t
}

// quarantine copies the program of pid into the state directory, readable
// by root only, named by its hash. Old copies expire; the total is capped.
func (a *Agent) quarantine(pid int, sha string) (string, string) {
	if a.cfg.Quarantine == nil || !*a.cfg.Quarantine || sha == "" {
		return "", ""
	}
	dir := filepath.Join(a.cfg.StateDir, "quarantine")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err.Error()
	}
	dst := filepath.Join(dir, sha)
	if _, err := os.Stat(dst); err == nil {
		return dst, ""
	}
	entries, _ := os.ReadDir(dir)
	var total int64
	for _, e := range entries {
		if fi, err := e.Info(); err == nil {
			if time.Since(fi.ModTime()) > quarantineMaxAge {
				os.Remove(filepath.Join(dir, e.Name()))
				continue
			}
			total += fi.Size()
		}
	}
	src, err := os.Open("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", err.Error()
	}
	defer src.Close()
	fi, err := src.Stat()
	if err != nil {
		return "", err.Error()
	}
	if fi.Size() > quarantineMax || total+fi.Size() > quarantineTotal {
		return "", "quarantine full or program too large"
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o400)
	if err != nil {
		return "", err.Error()
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), io.LimitReader(src, quarantineMax))
	out.Close()
	if err == nil && hex.EncodeToString(h.Sum(nil)) != sha {
		err = errString("program changed while it was copied")
	}
	if err != nil {
		os.Remove(tmp)
		return "", err.Error()
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return "", err.Error()
	}
	return dst, ""
}

type errString string

func (e errString) Error() string { return string(e) }

// snapshot collects and emits one evidence snapshot. trigger names what
// asked for it; request is the server's request id, if any.
func (a *Agent) snapshot(pid int, trigger, request, alert string) {
	if !on(a.cfg.Forensics) {
		if request != "" {
			a.emit(proto.NewEvent("forensics.snapshot", map[string]any{"request": request, "alert": alert, "error": "forensics is off in agent.json"}))
		}
		return
	}
	if !a.snaps.allow(pid, time.Now()) {
		if request != "" {
			a.emit(proto.NewEvent("forensics.snapshot", map[string]any{"request": request, "alert": alert, "error": "snapshot limit reached"}))
		}
		return
	}
	start := time.Now()
	// The suspect first, while it still runs.
	var target map[string]any
	if pid > 0 {
		target = targetDetail(pid)
	}
	owners := socketInodes()
	conns := listConns(owners)
	procs := listProcs()
	if pid > 0 {
		if gone, _ := target["gone"].(bool); !gone {
			var own []snapConn
			for _, c := range conns {
				if c.PID == pid {
					own = append(own, c)
				}
			}
			target["sockets"] = own
			var children []map[string]any
			for _, c := range procs {
				if c.PPID == pid && len(children) < 50 {
					children = append(children, map[string]any{"pid": c.PID, "comm": c.Comm, "exe": c.Exe})
				}
			}
			target["children"] = children
			if sha, _ := target["exe_sha256"].(string); sha != "" {
				if path, qerr := a.quarantine(pid, sha); path != "" {
					target["quarantined"] = path
				} else if qerr != "" {
					target["quarantine_error"] = qerr
				}
			}
		}
	}
	host, _ := os.Hostname()
	d := map[string]any{"trigger": trigger, "pid": pid, "hostname": host, "processes": procs, "connections": conns,
		"sessions": utmpSessions(), "modules": moduleNames(), "journal": journalTail(60)}
	if request != "" {
		d["request"] = request
	}
	if alert != "" {
		d["alert"] = alert
	}
	if target != nil {
		d["target"] = target
	}
	if len(procs) > snapMaxProcs {
		d["processes"] = procs[:snapMaxProcs]
		d["processes_truncated"] = len(procs)
	}
	if len(conns) > snapMaxConns {
		d["connections"] = conns[:snapMaxConns]
		d["connections_truncated"] = len(conns)
	}
	// Stay well below the batch limit: drop the bulkiest parts first.
	for _, k := range []string{"journal", "processes", "connections"} {
		raw, _ := json.Marshal(d)
		if len(raw) <= snapMaxBytes {
			break
		}
		delete(d, k)
		d[k+"_dropped"] = "snapshot too large"
	}
	d["seconds"] = time.Since(start).Seconds()
	raw, _ := json.Marshal(d)
	sum := sha256.Sum256(raw)
	d["sha256"] = hex.EncodeToString(sum[:])
	a.emit(proto.NewEvent("forensics.snapshot", d))
	a.flushSoon()
}

// runSnapshots runs the server's requests once each, before they expire.
func (a *Agent) runSnapshots(reqs []proto.SnapshotRequest) {
	if a.state.ActionsDone == nil {
		a.state.ActionsDone = map[string]time.Time{}
	}
	for _, r := range reqs {
		key := "snapshot:" + r.ID
		if _, done := a.state.ActionsDone[key]; done || r.ID == "" || len(r.ID) > 64 {
			continue
		}
		a.state.ActionsDone[key] = time.Now()
		if time.Now().After(r.Expires) {
			a.emit(proto.NewEvent("forensics.snapshot", map[string]any{"request": r.ID, "alert": r.Alert, "error": "expired before it reached the host"}))
			continue
		}
		go a.snapshot(r.PID, "request", r.ID, r.Alert)
	}
}

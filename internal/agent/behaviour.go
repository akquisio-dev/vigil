package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Behaviour: what people and programs do, beyond single suspicious starts.
//
// SSH sessions: every command typed in an SSH session (a program started by
// a shell, sudo or su inside the session) is reported with the session's
// sshd process, so the server can show who did what in which session. A
// session is recognised by its sshd process among the program's parents,
// and afterwards by its audit session id, which survives tmux and screen.
//
// Rarity: after a learning period the agent reports programs it has never
// seen run on this host (when no package installed them) and child
// programs a service never started before.
//
// Volume: bytes sent and received per hour, for the server to spot unusual
// outbound traffic.

const (
	sessionCmdsPerHour = 300
	rareLearnDefault   = 7 * 24 * time.Hour
	rareMaxExes        = 20000
	rareMaxPairs       = 5000
	auditUnset         = 4294967295
)

var interactiveParents = map[string]bool{"sshd": true, "sshd-session": true, "sudo": true, "su": true, "doas": true,
	"tmux: server": true, "tmux": true, "screen": true, "SCREEN": true, "login": true}

// rareParents start children that are worth learning: network services and
// runtimes that serve requests.
var rareParents = map[string]bool{"node": true, "java": true, "ruby": true, "gunicorn": true, "uwsgi": true, "srcds_linux": true,
	"php": true, "dotnet": true, "beam.smp": true, "containerd-shim": false}

type sshSession struct {
	PID   int
	User  string
	IP    string
	Start time.Time
	End   time.Time
	sent  int
	drops int
	hour  time.Time
}

type sessionTracker struct {
	mu     sync.Mutex
	byPID  map[int]*sshSession // sshd process of the login
	byAuid map[uint32]int      // audit session id -> sshd pid
}

func (st *sessionTracker) login(pid int, user, ip string, ts time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.byPID == nil {
		st.byPID, st.byAuid = map[int]*sshSession{}, map[uint32]int{}
	}
	st.byPID[pid] = &sshSession{PID: pid, User: user, IP: ip, Start: ts}
	// forget sessions that ended an hour ago
	for p, s := range st.byPID {
		if !s.End.IsZero() && time.Since(s.End) > time.Hour {
			delete(st.byPID, p)
		}
	}
	for a, p := range st.byAuid {
		if st.byPID[p] == nil {
			delete(st.byAuid, a)
		}
	}
}

func (st *sessionTracker) logout(pid int, ts time.Time) *sshSession {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.byPID[pid]
	if s != nil && s.End.IsZero() {
		s.End = ts
		return s
	}
	return nil
}

func procPPID(pid int) (int, string) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, ""
	}
	s := string(b)
	i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if i < 0 || j < i {
		return 0, ""
	}
	f := strings.Fields(s[j+1:])
	if len(f) < 2 {
		return 0, ""
	}
	ppid, _ := strconv.Atoi(f[1])
	return ppid, s[i+1 : j]
}

func readUint32File(path string) uint32 {
	b, err := os.ReadFile(path)
	if err != nil {
		return auditUnset
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil {
		return auditUnset
	}
	return uint32(n)
}

// session finds the SSH session a program belongs to.
func (st *sessionTracker) session(e *ExecInfo) *sshSession {
	if e.LoginUID == auditUnset {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.byPID == nil {
		return nil
	}
	if e.SessionID != auditUnset {
		if p, ok := st.byAuid[e.SessionID]; ok {
			if s := st.byPID[p]; s != nil {
				return s
			}
		}
	}
	cur := e.PPID
	for i := 0; i < 16 && cur > 1; i++ {
		if s := st.byPID[cur]; s != nil {
			if e.SessionID != auditUnset {
				st.byAuid[e.SessionID] = cur
			}
			return s
		}
		cur, _ = procPPID(cur)
	}
	return nil
}

// allow caps commands per session and hour. Commands dropped in the last
// hour are returned once, when the next hour starts.
func (s *sshSession) allow(now time.Time) (ok bool, dropped int) {
	if now.Sub(s.hour) >= time.Hour {
		dropped = s.drops
		s.hour, s.sent, s.drops = now, 0, 0
	}
	if s.sent >= sessionCmdsPerHour {
		s.drops++
		return false, dropped
	}
	s.sent++
	return true, dropped
}

func (a *Agent) sessionExec(e *ExecInfo) {
	if !on(a.cfg.Sessions) || !interactiveParents[e.ParentComm] && !shells[e.ParentComm] {
		return
	}
	s := a.sessions.session(e)
	if s == nil {
		return
	}
	a.sessions.mu.Lock()
	ok, dropped := s.allow(time.Now())
	user, ip, pid := s.User, s.IP, s.PID
	a.sessions.mu.Unlock()
	if dropped > 0 {
		a.emit(proto.NewEvent("session.dropped", map[string]any{"sshd_pid": pid, "user": user, "count": dropped}))
	}
	if !ok {
		return
	}
	a.emit(proto.NewEvent("session.exec", map[string]any{"sshd_pid": pid, "user": user, "ip": ip, "pid": e.PID, "ppid": e.PPID,
		"uid": e.UID, "exe": e.Exe, "cmdline": clipCmd(redactCmd(e.Cmdline)), "cwd": e.Cwd, "parent_comm": e.ParentComm}))
}

// ---------- rarity ----------

type RareState struct {
	Since time.Time       `json:"since"`
	Exes  map[string]bool `json:"exes"`
	Pairs map[string]bool `json:"pairs"`
	dirty bool
	mu    sync.Mutex
}

func rareStatePath(dir string) string { return filepath.Join(dir, "rare.json") }

func loadRare(dir string) *RareState {
	rs := &RareState{}
	if raw, err := os.ReadFile(rareStatePath(dir)); err == nil {
		json.Unmarshal(raw, rs)
	}
	if rs.Exes == nil {
		rs.Exes = map[string]bool{}
	}
	if rs.Pairs == nil {
		rs.Pairs = map[string]bool{}
	}
	if rs.Since.IsZero() {
		rs.Since, rs.dirty = time.Now().UTC(), true
	}
	return rs
}

func (rs *RareState) save(dir string) {
	rs.mu.Lock()
	if !rs.dirty {
		rs.mu.Unlock()
		return
	}
	raw, err := json.Marshal(rs)
	rs.dirty = false
	rs.mu.Unlock()
	if err == nil {
		writeFileAtomic(rareStatePath(dir), raw, 0o600)
	}
}

func (a *Agent) rareLearn() time.Duration {
	if a.cfg.RareLearnDays > 0 {
		return time.Duration(a.cfg.RareLearnDays) * 24 * time.Hour
	}
	return rareLearnDefault
}

var hostMntNS = func() string { l, _ := os.Readlink("/proc/1/ns/mnt"); return l }()

func isRareParent(comm string, extra []string) bool {
	if serviceParents[comm] || rareParents[comm] || strings.HasPrefix(comm, "php-fpm") || strings.HasPrefix(comm, "python") {
		return true
	}
	for _, x := range extra {
		if x == comm {
			return true
		}
	}
	return false
}

// rareExec learns every program start and reports the new ones once the
// learning period is over.
func (a *Agent) rareExec(e *ExecInfo) {
	if !on(a.cfg.Rarity) || a.rare == nil || e.Exe == "" || e.Deleted || strings.HasPrefix(e.Exe, "/memfd:") {
		return
	}
	// Programs inside containers have paths of their own image; runc
	// starts each container from a path inside the new container.
	if e.MntNS != "" && hostMntNS != "" && e.MntNS != hostMntNS || strings.HasPrefix(e.Comm, "runc") || strings.HasPrefix(e.ParentComm, "runc") {
		return
	}
	for _, d := range tmpDirs {
		if strings.HasPrefix(e.Exe, d) {
			return // process.tmp_exec already reports these
		}
	}
	rs := a.rare
	learned := time.Since(rs.Since) >= a.rareLearn()
	pair := ""
	if isRareParent(e.ParentComm, a.cfg.RareParents) {
		pair = e.ParentComm + "|" + filepath.Base(e.Exe)
	}
	rs.mu.Lock()
	newExe := !rs.Exes[e.Exe] && len(rs.Exes) < rareMaxExes
	newPair := pair != "" && !rs.Pairs[pair] && len(rs.Pairs) < rareMaxPairs
	if newExe {
		rs.Exes[e.Exe], rs.dirty = true, true
	}
	if newPair {
		rs.Pairs[pair], rs.dirty = true, true
	}
	rs.mu.Unlock()
	if !learned || !newExe && !newPair {
		return
	}
	d := map[string]any{"pid": e.PID, "uid": e.UID, "exe": e.Exe, "comm": e.Comm, "cmdline": clipCmd(redactCmd(e.Cmdline)),
		"parent_comm": e.ParentComm, "parent_exe": e.ParentExe, "cwd": e.Cwd}
	if newPair {
		a.emit(proto.NewEvent("process.rare_child", d))
	}
	if newExe {
		// A program a package installed (an update, a new tool from apt)
		// is expected; only unpackaged ones are reported.
		go func() {
			info := lookupDpkg([]string{e.Exe})
			if info.ok && info.owner[e.Exe] != "" {
				return
			}
			a.emit(proto.NewEvent("process.rare", d))
		}()
	}
}

func (a *Agent) runRare(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.rare.save(a.cfg.StateDir)
			return
		case <-t.C:
			a.rare.save(a.cfg.StateDir)
		}
	}
}

// ---------- traffic volume ----------

type ifaceBytes struct{ rx, tx uint64 }

// skipIface leaves out loopback and virtual interfaces, whose traffic is
// counted again on the physical one.
func skipIface(name string) bool {
	for _, p := range []string{"lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "cali", "vnet", "tap"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func readNetDev(path string) map[string]ifaceBytes {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]ifaceBytes{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		fl := strings.Fields(rest)
		if len(fl) < 9 || skipIface(name) {
			continue
		}
		rx, _ := strconv.ParseUint(fl[0], 10, 64)
		tx, _ := strconv.ParseUint(fl[8], 10, 64)
		out[name] = ifaceBytes{rx, tx}
	}
	return out
}

// volumeDelta sums the bytes since the last reading; a counter that went
// down (interface reset) counts from zero.
func volumeDelta(prev, cur map[string]ifaceBytes) (rx, tx uint64) {
	for n, c := range cur {
		p, ok := prev[n]
		if !ok {
			continue
		}
		if c.rx >= p.rx {
			rx += c.rx - p.rx
		} else {
			rx += c.rx
		}
		if c.tx >= p.tx {
			tx += c.tx - p.tx
		} else {
			tx += c.tx
		}
	}
	return
}

func (a *Agent) runVolume(ctx context.Context) {
	prev := readNetDev("/proc/net/dev")
	last := time.Now()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := readNetDev("/proc/net/dev")
			rx, tx := volumeDelta(prev, cur)
			a.emit(proto.NewEvent("net.volume", map[string]any{"rx_bytes": rx, "tx_bytes": tx, "seconds": int(time.Since(last).Seconds())}))
			prev, last = cur, time.Now()
		}
	}
}

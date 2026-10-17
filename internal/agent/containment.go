package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Containment: isolating the host from the network and locking accounts.
// Both end by themselves: the agent keeps the end time in its state and
// undoes the measure when it is reached, also after a restart or reboot,
// without waiting for the server. Isolation keeps the vigil server and the
// addresses in isolate_allow (or never_block) reachable, so the people who
// investigate are not locked out; without such an address it is refused.

const (
	isolateMaxMinutes = 24 * 60
	lockMaxMinutes    = 30 * 24 * 60
	nftIsolateTable   = "vigil_isolate"
)

var userName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// ContainState is kept in state.json.
type ContainState struct {
	IsolatedUntil time.Time           `json:"isolated_until,omitempty"`
	IsolatedBy    string              `json:"isolated_by,omitempty"` // action id
	Locked        map[string]LockInfo `json:"locked,omitempty"`
}

type LockInfo struct {
	Until      time.Time `json:"until"`
	PrevExpire string    `json:"prev_expire"` // field 8 of /etc/shadow before the lock
	Action     string    `json:"action"`
}

// ---------- isolation ----------

func (a *Agent) isolateAllow() ([]allowNet, error) {
	var out []allowNet
	add := func(s string) {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, allowNet{n})
			return
		}
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, allowNet{&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}})
		}
	}
	admins := 0
	if r := a.cfg.Response; r != nil {
		for _, s := range append(append([]string{}, r.IsolateAllow...), r.NeverBlock...) {
			before := len(out)
			add(s)
			admins += len(out) - before
		}
	}
	if admins == 0 {
		return nil, errors.New("refusing to isolate: no address in isolate_allow or never_block, nobody could reach the host")
	}
	host := serverHost(a.cfg.Server)
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("refusing to isolate: cannot resolve the vigil server %q", host)
	}
	for _, ip := range addrs {
		add(ip.String())
	}
	return out, nil
}

type allowNet struct{ n *net.IPNet }

func isolateRuleset(allow []allowNet) string {
	var v4, v6 []string
	for _, a := range allow {
		if a.n.IP.To4() != nil {
			v4 = append(v4, a.n.String())
		} else {
			v6 = append(v6, a.n.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	set := func(name, typ string, elems []string) string {
		s := fmt.Sprintf("\tset %s { type %s; flags interval; ", name, typ)
		if len(elems) > 0 {
			s += "elements = { " + strings.Join(elems, ", ") + " }; "
		}
		return s + "}\n"
	}
	var b strings.Builder
	b.WriteString("table inet " + nftIsolateTable + " {\n")
	b.WriteString(set("allow4", "ipv4_addr", v4))
	b.WriteString(set("allow6", "ipv6_addr", v6))
	// Priority -20 runs before the host's own firewall (ufw, Docker), so
	// nothing it accepts gets past the isolation.
	b.WriteString("\tchain input { type filter hook input priority -20; policy drop; iif lo accept; ip saddr @allow4 accept; ip6 saddr @allow6 accept; ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept; }\n")
	b.WriteString("\tchain output { type filter hook output priority -20; policy drop; oif lo accept; ip daddr @allow4 accept; ip6 daddr @allow6 accept; ip6 nexthdr icmpv6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept; }\n")
	b.WriteString("\tchain forward { type filter hook forward priority -20; policy drop; }\n")
	b.WriteString("}\n")
	return b.String()
}

func (a *Agent) applyIsolation() error {
	allow, err := a.isolateAllow()
	if err != nil {
		return err
	}
	runNft("", "delete", "table", "inet", nftIsolateTable)
	return runNft(isolateRuleset(allow), "-f", "-")
}

func (a *Agent) isolate(act proto.Action) (string, error) {
	mins, _ := strconv.Atoi(act.Params["minutes"])
	if mins <= 0 {
		mins = 60
	}
	if mins > isolateMaxMinutes {
		mins = isolateMaxMinutes
	}
	if err := a.applyIsolation(); err != nil {
		return "", err
	}
	until := time.Now().UTC().Add(time.Duration(mins) * time.Minute)
	a.mu.Lock()
	a.state.Contain.IsolatedUntil, a.state.Contain.IsolatedBy = until, act.ID
	a.mu.Unlock()
	a.saveState()
	return fmt.Sprintf("host isolated until %s UTC (nft table inet %s); only the vigil server and isolate_allow can reach it", until.Format("2006-01-02 15:04"), nftIsolateTable), nil
}

func (a *Agent) release(reason string) (string, error) {
	a.mu.Lock()
	was := !a.state.Contain.IsolatedUntil.IsZero()
	a.state.Contain.IsolatedUntil, a.state.Contain.IsolatedBy = time.Time{}, ""
	a.mu.Unlock()
	err := runNft("", "delete", "table", "inet", nftIsolateTable)
	a.saveState()
	if err != nil && was {
		return "", err
	}
	return "isolation ended (" + reason + ")", nil
}

// ---------- account locks ----------

// shadowExpire reads field 8 (account expiry) of a user in /etc/shadow.
func shadowExpire(user string) (string, error) {
	b, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 9 && f[0] == user {
			return f[7], nil
		}
	}
	return "", fmt.Errorf("no account %q", user)
}

func uidOf(user string) (int, error) {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return -1, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 7 && f[0] == user {
			return strconv.Atoi(f[2])
		}
	}
	return -1, fmt.Errorf("no account %q", user)
}

// runAccountTool runs usermod. The agent's unit makes /etc read-only, so
// when that fails it asks systemd to run the same command outside the
// agent's sandbox (systemd-run). Only fixed commands with a checked user
// name ever get there.
func runAccountTool(args ...string) error {
	run := func(bin string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %v %s", filepath.Base(bin), err, strings.TrimSpace(stderr.String()))
		}
		return nil
	}
	usermod, err := exec.LookPath("usermod")
	if err != nil {
		return errors.New("usermod not installed")
	}
	err = run(usermod, args...)
	if err == nil {
		return nil
	}
	sr, lerr := exec.LookPath("systemd-run")
	if lerr != nil {
		return err
	}
	if err2 := run(sr, append([]string{"--wait", "--quiet", "--collect", "-p", "ProtectSystem=no", usermod}, args...)...); err2 != nil {
		return fmt.Errorf("%v; through systemd-run: %v", err, err2)
	}
	return nil
}

func (a *Agent) refuseLock(user string) error {
	if !userName.MatchString(user) {
		return errors.New("not a valid user name")
	}
	uid, err := uidOf(user)
	if err != nil {
		return err
	}
	if uid == 0 {
		return errors.New("refusing to lock an account with uid 0 (lockout)")
	}
	if r := a.cfg.Response; r != nil {
		for _, n := range r.NeverLock {
			if n == user {
				return errors.New("account is in never_lock")
			}
		}
	}
	return nil
}

// endUserSessions stops the SSH sessions of a user (the sshd processes
// running as that user, "sshd: user@pts/0").
func endUserSessions(user string) int {
	n := 0
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		comm, _ := os.ReadFile(d + "/comm")
		c := strings.TrimSpace(string(comm))
		if c != "sshd" && c != "sshd-session" {
			continue
		}
		cmd, _ := os.ReadFile(d + "/cmdline")
		line := strings.TrimRight(strings.ReplaceAll(string(cmd), "\x00", " "), " ")
		if strings.HasPrefix(line, "sshd: "+user+"@") || strings.HasPrefix(line, "sshd-session: "+user+"@") || line == "sshd: "+user+" [priv]" || line == "sshd-session: "+user+" [priv]" {
			if pid, err := strconv.Atoi(filepath.Base(d)); err == nil && terminate(pid) == nil {
				n++
			}
		}
	}
	return n
}

func (a *Agent) lockUser(act proto.Action) (string, error) {
	user := act.Params["user"]
	if err := a.refuseLock(user); err != nil {
		return "", err
	}
	mins, _ := strconv.Atoi(act.Params["minutes"])
	if mins <= 0 {
		mins = 24 * 60
	}
	if mins > lockMaxMinutes {
		mins = lockMaxMinutes
	}
	prev, err := shadowExpire(user)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	if old, ok := a.state.Contain.Locked[user]; ok {
		prev = old.PrevExpire // already locked: keep the original expiry
	}
	a.mu.Unlock()
	// -L locks the password, -e 1 expires the account, which also stops
	// logins with SSH keys (PAM account check).
	if err := runAccountTool("-L", "-e", "1", user); err != nil {
		return "", err
	}
	until := time.Now().UTC().Add(time.Duration(mins) * time.Minute)
	a.mu.Lock()
	if a.state.Contain.Locked == nil {
		a.state.Contain.Locked = map[string]LockInfo{}
	}
	a.state.Contain.Locked[user] = LockInfo{Until: until, PrevExpire: prev, Action: act.ID}
	a.mu.Unlock()
	a.saveState()
	ended := endUserSessions(user)
	return fmt.Sprintf("account %s locked until %s UTC, %d SSH sessions ended", user, until.Format("2006-01-02 15:04"), ended), nil
}

func (a *Agent) unlockUser(user, reason string) (string, error) {
	if !userName.MatchString(user) {
		return "", errors.New("not a valid user name")
	}
	a.mu.Lock()
	info, ok := a.state.Contain.Locked[user]
	a.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("%s was not locked by vigil", user)
	}
	// field 8 holds days since 1970; "" means the account never expires
	args := []string{"-U", "-e", "", user}
	if n, err := strconv.Atoi(info.PrevExpire); err == nil {
		args = []string{"-U", "-e", time.Unix(int64(n)*86400, 0).UTC().Format("2006-01-02"), user}
	}
	if err := runAccountTool(args...); err != nil {
		return "", err
	}
	a.mu.Lock()
	delete(a.state.Contain.Locked, user)
	a.mu.Unlock()
	a.saveState()
	return "account " + user + " unlocked (" + reason + ")", nil
}

// ---------- expiry ----------

// checkContainment undoes measures whose time is up and restores an
// isolation lost by a reboot. It runs with every scan.
func (a *Agent) checkContainment() {
	now := time.Now().UTC()
	a.mu.Lock()
	until := a.state.Contain.IsolatedUntil
	var due []string
	for u, l := range a.state.Contain.Locked {
		if now.After(l.Until) {
			due = append(due, u)
		}
	}
	a.mu.Unlock()
	if !until.IsZero() {
		if now.After(until) {
			detail, err := a.release("time is up")
			a.containEvent("release_host", detail, err)
		} else if runNft("", "list", "table", "inet", nftIsolateTable) != nil {
			// gone after a reboot or removed by hand: put it back
			err := a.applyIsolation()
			a.containEvent("isolate_host", "isolation restored until "+until.Format("2006-01-02 15:04")+" UTC", err)
		}
	}
	for _, u := range due {
		detail, err := a.unlockUser(u, "time is up")
		a.containEvent("unlock_user", detail, err)
	}
}

func (a *Agent) containEvent(typ, detail string, err error) {
	d := map[string]any{"type": typ, "ok": err == nil, "detail": detail, "automatic": true}
	if err != nil {
		d["error"] = err.Error()
	}
	a.emit(proto.NewEvent("response.result", d))
	a.reportContainment()
}

// reportContainment tells the server what is in force.
func (a *Agent) reportContainment() {
	a.mu.Lock()
	d := map[string]any{}
	if !a.state.Contain.IsolatedUntil.IsZero() {
		d["isolated_until"] = a.state.Contain.IsolatedUntil
	}
	locked := map[string]any{}
	for u, l := range a.state.Contain.Locked {
		locked[u] = l.Until
	}
	d["locked"] = locked
	a.mu.Unlock()
	a.emit(proto.NewEvent("response.state", d))
}

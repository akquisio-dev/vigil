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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Response actions let an admin contain an attack from the dashboard. They
// widen what a compromised server could do to this host, so they are off
// unless agent.json enables them, each type must be allowed there, and the
// agent checks every parameter itself. Arbitrary commands are not possible.

type ResponseConfig struct {
	Enabled bool `json:"enabled"`
	// Allow lists the action types this host accepts; empty means all.
	Allow []string `json:"allow,omitempty"`
	// NeverBlock lists addresses or networks block_ip refuses, for example
	// the admins' VPN. Loopback and the vigil server are always refused.
	NeverBlock []string `json:"never_block,omitempty"`
}

func (r *ResponseConfig) allows(t string) bool {
	if r == nil || !r.Enabled {
		return false
	}
	if len(r.Allow) == 0 {
		return true
	}
	for _, a := range r.Allow {
		if a == t {
			return true
		}
	}
	return false
}

func (a *Agent) runActions(actions []proto.Action) {
	now := time.Now()
	if a.state.ActionsDone == nil {
		a.state.ActionsDone = map[string]time.Time{}
	}
	for id, at := range a.state.ActionsDone {
		if now.Sub(at) > 7*24*time.Hour {
			delete(a.state.ActionsDone, id)
		}
	}
	for _, act := range actions {
		if _, done := a.state.ActionsDone[act.ID]; done || act.ID == "" {
			continue
		}
		a.state.ActionsDone[act.ID] = now
		var detail string
		var err error
		switch {
		case now.After(act.Expires):
			err = errors.New("expired before it reached the host")
		case !a.cfg.Response.allows(act.Type):
			err = errors.New("not allowed on this host (response in agent.json)")
		default:
			detail, err = a.doAction(act)
		}
		d := map[string]any{"action_id": act.ID, "type": act.Type, "ok": err == nil, "detail": detail}
		if err != nil {
			d["error"] = err.Error()
		}
		a.emit(proto.NewEvent("response.result", d))
	}
}

func (a *Agent) doAction(act proto.Action) (string, error) {
	p := act.Params
	switch act.Type {
	case "block_ip":
		mins, _ := strconv.Atoi(p["minutes"])
		return a.blockIP(p["ip"], mins)
	case "kill_session":
		pid, _ := strconv.Atoi(p["sshd_pid"])
		return killSession(pid, p["user"])
	case "kill_process":
		pid, _ := strconv.Atoi(p["pid"])
		return killProcess(pid, p["exe"])
	case "remove_key":
		return removeAuthorizedKey(p["file"], p["fingerprint"], a.cfg.StateDir)
	}
	return "", fmt.Errorf("unknown action %q", act.Type)
}

// ---------- block_ip: an nftables set with timeouts, in its own table ----------

const nftTable = `table inet vigil {
	set blocked4 { type ipv4_addr; flags timeout; }
	set blocked6 { type ipv6_addr; flags timeout; }
	chain input { type filter hook input priority -10; policy accept; ip saddr @blocked4 drop; ip6 saddr @blocked6 drop; }
	chain forward { type filter hook forward priority -10; policy accept; ip saddr @blocked4 drop; ip6 saddr @blocked6 drop; ip daddr @blocked4 drop; ip6 daddr @blocked6 drop; }
	chain output { type filter hook output priority -10; policy accept; ip daddr @blocked4 drop; ip6 daddr @blocked6 drop; }
}
`

func runNft(stdin string, args ...string) error {
	bin, err := exec.LookPath("nft")
	if err != nil {
		return errors.New("nft not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (a *Agent) refuseBlock(ip net.IP) error {
	if ip == nil {
		return errors.New("not an IP address")
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return errors.New("refusing to block a local address")
	}
	if host := serverHost(a.cfg.Server); host != "" {
		addrs, _ := net.LookupIP(host)
		for _, s := range addrs {
			if s.Equal(ip) {
				return errors.New("refusing to block the vigil server")
			}
		}
	}
	for _, n := range a.cfg.Response.NeverBlock {
		if _, cidr, err := net.ParseCIDR(n); err == nil && cidr.Contains(ip) {
			return errors.New("address is in never_block")
		}
		if x := net.ParseIP(n); x != nil && x.Equal(ip) {
			return errors.New("address is in never_block")
		}
	}
	return nil
}

func serverHost(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	host, _, err := net.SplitHostPort(strings.SplitN(u, "/", 2)[0])
	if err != nil {
		return strings.SplitN(u, "/", 2)[0]
	}
	return host
}

func (a *Agent) blockIP(s string, minutes int) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if err := a.refuseBlock(ip); err != nil {
		return "", err
	}
	if minutes <= 0 {
		minutes = 24 * 60
	}
	if minutes > 30*24*60 {
		minutes = 30 * 24 * 60
	}
	if runNft("", "list", "table", "inet", "vigil") != nil {
		if err := runNft(nftTable, "-f", "-"); err != nil {
			return "", err
		}
	}
	set := "blocked4"
	if ip.To4() == nil {
		set = "blocked6"
	}
	elem := fmt.Sprintf("{ %s timeout %dm }", ip.String(), minutes)
	if err := runNft("", "add", "element", "inet", "vigil", set, elem); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s blocked for %d minutes (nft table inet vigil)", ip, minutes), nil
}

// ---------- kill_session / kill_process ----------

func procComm(pid int) string {
	b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	return strings.TrimSpace(string(b))
}

func terminate(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return err
	}
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		if syscall.Kill(pid, 0) != nil {
			return nil
		}
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}

func killSession(pid int, user string) (string, error) {
	if pid <= 1 || pid == os.Getpid() {
		return "", errors.New("bad pid")
	}
	comm := procComm(pid)
	if comm != "sshd" && comm != "sshd-session" {
		return "", fmt.Errorf("pid %d is %q, not an SSH session (ended already?)", pid, comm)
	}
	cmd, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if user != "" && !strings.Contains(string(cmd), user) {
		return "", fmt.Errorf("pid %d does not belong to %s", pid, user)
	}
	if strings.Contains(string(cmd), "-D") || strings.HasSuffix(strings.TrimRight(string(cmd), "\x00"), "sshd") {
		return "", errors.New("refusing to stop the SSH daemon itself")
	}
	if err := terminate(pid); err != nil {
		return "", err
	}
	return fmt.Sprintf("SSH session %d of %s ended", pid, user), nil
}

func killProcess(pid int, exe string) (string, error) {
	if pid <= 1 || pid == os.Getpid() || pid == os.Getppid() {
		return "", errors.New("bad pid")
	}
	cur, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", fmt.Errorf("process %d is gone", pid)
	}
	// the pid may have been reused: only kill if it still runs the same program
	if strings.TrimSuffix(cur, " (deleted)") != exe {
		return "", fmt.Errorf("pid %d now runs %s, not %s", pid, cur, exe)
	}
	if err := terminate(pid); err != nil {
		return "", err
	}
	return fmt.Sprintf("process %d (%s) stopped", pid, exe), nil
}

// ---------- remove_key ----------

// keyRoots are where remove_key may touch files (tests point it elsewhere).
var keyRoots = []string{"/root/.ssh/", "/home/"}

func removeAuthorizedKey(file, fingerprint, stateDir string) (string, error) {
	clean := filepath.Clean(file)
	base := filepath.Base(clean)
	under := false
	for _, r := range keyRoots {
		under = under || strings.HasPrefix(clean, r)
	}
	if clean != file || (base != "authorized_keys" && base != "authorized_keys2") || !under {
		return "", errors.New("not an authorized_keys file")
	}
	fi, err := os.Lstat(clean)
	if err != nil || !fi.Mode().IsRegular() {
		return "", errors.New("file missing or not a regular file")
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return "", err
	}
	var keep []string
	removed, remaining := 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		keys := ParseAuthorizedKeys([]byte(line))
		if len(keys) == 1 && keys[0].Fingerprint == fingerprint {
			removed++
			continue
		}
		if len(keys) == 1 {
			remaining++
		}
		keep = append(keep, line)
	}
	if removed == 0 {
		return "", errors.New("key not found in the file")
	}
	if remaining == 0 {
		return "", errors.New("refusing to remove the last key of this file (lockout)")
	}
	bdir := filepath.Join(stateDir, "backups")
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		return "", err
	}
	backup := filepath.Join(bdir, time.Now().UTC().Format("20060102T150405Z")+strings.ReplaceAll(clean, "/", "_"))
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		return "", err
	}
	// Rewritten in place, so owner and mode stay as they are (the agent has
	// no CAP_CHOWN); the backup above covers a failed write.
	if err := os.WriteFile(clean, []byte(strings.Join(keep, "\n")), fi.Mode().Perm()); err != nil {
		return "", err
	}
	return fmt.Sprintf("removed %s from %s (backup %s)", fingerprint, clean, backup), nil
}

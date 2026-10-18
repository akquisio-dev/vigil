package agent

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config is the local agent configuration (/etc/vigil/agent.json). Everything
// that limits what the server may ask of the agent lives here and only here.
type Config struct {
	Server   string `json:"server"`
	StateDir string `json:"state_dir"`

	IntervalSeconds int `json:"interval_seconds"`
	ScanSeconds     int `json:"scan_seconds"`

	// WatchFiles replaces the built-in watch list when set; ExtraWatch is
	// appended to it. Both accept shell globs.
	WatchFiles []string `json:"watch_files,omitempty"`
	ExtraWatch []string `json:"extra_watch,omitempty"`

	// CanaryRoots are the only directories below which the dashboard may
	// place canaries. Empty means canaries are disabled on this host.
	CanaryRoots []string `json:"canary_roots"`
	// CanaryIgnoreExe lists executables whose opens of a canary are not
	// reported (backup tools, indexers). Keep this list in private config.
	CanaryIgnoreExe []string `json:"canary_ignore_exe,omitempty"`

	SSH    *bool `json:"ssh,omitempty"`
	Ports  *bool `json:"ports,omitempty"`
	Docker *bool `json:"docker,omitempty"`
	// Processes watches program starts through the kernel's process events
	// connector and reports the suspicious ones.
	Processes *bool `json:"processes,omitempty"`
	// Kernel watches loaded kernel modules, modules hidden from
	// /proc/modules and new kernel taint flags.
	Kernel *bool `json:"kernel,omitempty"`
	// Suid walks local filesystems for SUID/SGID programs and files with
	// capabilities (every 6 hours, temp directories every 5 minutes).
	Suid *bool `json:"suid,omitempty"`
	// Integrity compares login and inspection programs, PAM modules and core
	// libraries with their Debian package checksums (every 6 hours).
	Integrity *bool `json:"integrity,omitempty"`
	// BPF reports newly loaded eBPF programs that can hook the kernel or the
	// network path (kprobe, tracepoint, tracing, lsm, xdp and similar).
	BPF *bool `json:"bpf,omitempty"`
	// Updates reports pending (security) updates and pending reboots.
	Updates *bool `json:"updates,omitempty"`
	// Outbound reports new outbound TCP destinations with their process.
	Outbound *bool `json:"outbound,omitempty"`
	// Response allows response actions from the dashboard. Off by default.
	Response *ResponseConfig `json:"response,omitempty"`
	// SelfUpdate lets the server ask for a newer signed release, which the
	// vigil-agent-update units install. Off by default.
	SelfUpdate bool `json:"self_update,omitempty"`
	// SelfTest lets the server ask for a self test: a comment-only file in
	// /etc/cron.d, a copy of `sleep` started from /tmp and an sshd-tagged log
	// line, all removed right away. On by default.
	SelfTest *bool `json:"selftest,omitempty"`
	// Posture reports hardening checks (SSH, accounts, kernel settings, file
	// permissions, firewall, AppArmor/SELinux), TLS certificates and backups
	// every six hours.
	Posture *bool `json:"posture,omitempty"`
	// PostureSkip lists checks not to run, by name ("firewall") or by name
	// and key ("sysctl:kernel.dmesg_restrict").
	PostureSkip []string `json:"posture_skip,omitempty"`
	// TLSCerts are extra certificate files (globs) to watch for expiry, on
	// top of Let's Encrypt and what nginx and Apache configurations name.
	TLSCerts []string `json:"tls_certs,omitempty"`
	// Backups are locations whose newest file must not be older than
	// max_age_hours. Empty by default.
	Backups []Backup `json:"backups,omitempty"`
	// Secrets looks for private keys, tokens and credentials that every user
	// on the host can read (once a day).
	Secrets *bool `json:"secrets,omitempty"`
	// SecretRoots replaces the directories searched for exposed secrets.
	SecretRoots []string `json:"secret_roots,omitempty"`
	// Packages sends the installed package list to the server once a day,
	// so it can match it against vulnerability data (server option
	// vuln_lookup). The agent itself never contacts third parties.
	Packages *bool `json:"packages,omitempty"`
	// Forensics takes evidence snapshots (processes, sockets, sessions,
	// modules, journal tail, the suspect process in detail) on the agent's
	// strongest signals and when the server asks. Read only. On by default.
	Forensics *bool `json:"forensics,omitempty"`
	// Quarantine also copies the suspect program into the state directory
	// (root only, 30 days, 512 MB at most). Off by default.
	Quarantine *bool `json:"quarantine,omitempty"`
	// Sessions reports the commands typed in SSH sessions (programs started
	// by a shell, sudo or su inside the session), at most 300 per session
	// and hour. On by default.
	Sessions *bool `json:"sessions,omitempty"`
	// Rarity reports, after a learning period, programs never seen run on
	// this host (unless a package installed them) and children a service
	// never started before. On by default.
	Rarity *bool `json:"rarity,omitempty"`
	// RareLearnDays is the learning period (default 7).
	RareLearnDays int `json:"rare_learn_days,omitempty"`
	// RareParents adds process names whose children are learned, on top of
	// web servers, databases and common runtimes.
	RareParents []string `json:"rare_parents,omitempty"`
	// RareIgnore adds path parts whose programs are not learned (build
	// output directories, for example).
	RareIgnore []string `json:"rare_ignore,omitempty"`
	// Yara accepts YARA rules from the server and scans suspicious and new
	// programs and new programs in temp directories with them. On by
	// default; without rules on the server nothing is scanned.
	Yara *bool `json:"yara,omitempty"`
	// Volume reports bytes sent and received per hour.
	Volume *bool `json:"volume,omitempty"`
	// WebLogs are access logs to watch for scans and attacks.
	WebLogs []WebLog `json:"web_logs,omitempty"`

	MaxQueue int `json:"max_queue"`
}

func (c *Config) interval() time.Duration { return time.Duration(c.IntervalSeconds) * time.Second }
func (c *Config) scan() time.Duration     { return time.Duration(c.ScanSeconds) * time.Second }

func on(b *bool) bool { return b == nil || *b }

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/vigil-agent"
	}
	if c.IntervalSeconds <= 0 {
		c.IntervalSeconds = 30
	}
	if c.ScanSeconds <= 0 {
		c.ScanSeconds = 60
	}
	if c.MaxQueue <= 0 {
		c.MaxQueue = 5000
	}
	for i, r := range c.CanaryRoots {
		r = filepath.Clean(r)
		if !filepath.IsAbs(r) || r == "/" {
			return nil, fmt.Errorf("canary_roots: %q must be an absolute directory other than /", r)
		}
		c.CanaryRoots[i] = r
	}
	return &c, nil
}

// Identity is written once by `vigil-agent enroll`.
type Identity struct {
	AgentID    string             `json:"agent_id"`
	Server     string             `json:"server"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	ServerKey  ed25519.PublicKey  `json:"server_key"`
}

func identityPath(stateDir string) string { return filepath.Join(stateDir, "identity.json") }

func LoadIdentity(stateDir string) (*Identity, error) {
	raw, err := os.ReadFile(identityPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("agent is not enrolled, run `vigil-agent enroll` first")
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, err
	}
	if len(id.PrivateKey) != ed25519.PrivateKeySize || len(id.ServerKey) != ed25519.PublicKeySize {
		return nil, errors.New("identity.json is damaged")
	}
	return &id, nil
}

func SaveIdentity(stateDir string, id *Identity) error {
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(identityPath(stateDir), raw, 0o600)
}

// writeFileAtomic writes via a temp file and rename, so a crash never leaves
// a half-written state file behind.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

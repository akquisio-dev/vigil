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

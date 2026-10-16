package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type AgentRec struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Hostname  string    `json:"hostname"`
	PublicKey string    `json:"public_key"`
	Version   string    `json:"version"`
	Enrolled  time.Time `json:"enrolled"`
	LastSeen  time.Time `json:"last_seen"`
	LastSeq   int64     `json:"last_seq"`
	LastIP    string    `json:"last_ip"`

	Silent  bool `json:"silent"`
	Stopped bool `json:"stopped"`
	// StartedOnce separates the first start after enrollment from restarts.
	StartedOnce bool `json:"started_once"`
	// MaintenanceUntil is set from the dashboard only. A stop announced by
	// the agent itself never lowers anything, because the host announcing
	// it may be the one under attack.
	MaintenanceUntil time.Time `json:"maintenance_until,omitempty"`

	prevSeen time.Time // LastSeen before the batch being evaluated

	CanaryRoots []string `json:"canary_roots"`

	Ports       []map[string]any `json:"ports"`
	Baseline    map[string]bool  `json:"baseline"`
	BaselineSet bool             `json:"baseline_set"`

	ConfigVersion int64 `json:"config_version"`
	AckedVersion  int64 `json:"acked_version"`

	// Updates is the host's latest patch state as reported by the agent.
	Updates map[string]any `json:"updates,omitempty"`
}

type EnrollToken struct {
	Hash    string    `json:"hash"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	By      string    `json:"by"`
}

type CanaryRec struct {
	ID        string            `json:"id"`
	AgentID   string            `json:"agent_id"`
	Type      string            `json:"type"`
	Path      string            `json:"path"`
	Params    map[string]string `json:"params,omitempty"`
	Created   time.Time         `json:"created"`
	By        string            `json:"by"`
	Status    string            `json:"status"` // pending | active | tampered | error
	Error     string            `json:"error,omitempty"`
	Triggers  int               `json:"triggers"`
	LastTrigg time.Time         `json:"last_triggered,omitempty"`
}

type Alert struct {
	ID        string     `json:"id"`
	Key       string     `json:"key"`
	Rule      string     `json:"rule"`
	Severity  string     `json:"severity"`
	Technique string     `json:"technique,omitempty"`
	Title     string     `json:"title"`
	Detail    string     `json:"detail,omitempty"`
	Agent     string     `json:"agent,omitempty"`
	Created   time.Time  `json:"created"`
	Updated   time.Time  `json:"updated"`
	Count     int        `json:"count"`
	Status    string     `json:"status"` // open | acked | resolved
	By        string     `json:"by,omitempty"`
	Acked     *time.Time `json:"acked,omitempty"` // first time a person acknowledged or resolved it
	Incident  string     `json:"incident,omitempty"`
	Seqs      []uint64   `json:"seqs"`
}

type User struct {
	Name       string    `json:"name"`
	PassHash   string    `json:"pass_hash"`
	TOTPSecret string    `json:"totp_secret"`
	Created    time.Time `json:"created"`
	LastLogin  time.Time `json:"last_login,omitempty"`
	LastTOTP   int64     `json:"last_totp,omitempty"`
	// Role is viewer, analyst or admin; empty (older accounts) means admin.
	Role            string     `json:"role,omitempty"`
	Passkeys        []*Passkey `json:"passkeys,omitempty"`
	PasswordChanged time.Time  `json:"password_changed,omitempty"`
}

type State struct {
	Agents       map[string]*AgentRec    `json:"agents"`
	Tokens       map[string]*EnrollToken `json:"tokens"`
	Canaries     map[string]*CanaryRec   `json:"canaries"`
	Alerts       []*Alert                `json:"alerts"`
	KnownLogins  map[string]time.Time    `json:"known_logins"` // "user|ip"
	Suppressions []*Suppression          `json:"suppressions"`
	Incidents    []*Incident             `json:"incidents"`
	LastAnchor   time.Time               `json:"last_anchor"`
}

const maxAlerts = 5000

func stateFile(dir string) string { return filepath.Join(dir, "state.json") }

func LoadState(dir string) (*State, error) {
	s := &State{}
	raw, err := os.ReadFile(stateFile(dir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(raw, s); err != nil {
			return nil, err
		}
	}
	if s.Agents == nil {
		s.Agents = map[string]*AgentRec{}
	}
	if s.Tokens == nil {
		s.Tokens = map[string]*EnrollToken{}
	}
	if s.Canaries == nil {
		s.Canaries = map[string]*CanaryRec{}
	}
	if s.KnownLogins == nil {
		s.KnownLogins = map[string]time.Time{}
	}
	return s, nil
}

func (s *State) Save(dir string) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
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
	return os.Rename(tmp.Name(), stateFile(dir))
}

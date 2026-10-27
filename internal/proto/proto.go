// Package proto holds the wire format shared by vigil-agent and vigil-server.
//
// Agents only ever make outbound HTTP requests. Every request body is signed
// with the agent's ed25519 key, every configuration the server hands back is
// signed with the server's ed25519 key. Both keys are exchanged once during
// enrollment, so the transport itself (plain HTTP over a VPN, or HTTPS) does
// not have to be trusted for integrity.
package proto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// SigHeader carries the base64 ed25519 signature over the raw request or
// config body.
const SigHeader = "X-Vigil-Signature"

// MaxBodyBytes caps every agent request on the server side.
const MaxBodyBytes = 1 << 20

// Event is a single observation made by an agent (or by the server itself).
// Severity is decided by the server's rules, never by the agent.
type Event struct {
	Type string         `json:"type"`
	TS   time.Time      `json:"ts"`
	Data map[string]any `json:"data,omitempty"`
}

func NewEvent(typ string, data map[string]any) Event {
	return Event{Type: typ, TS: time.Now().UTC(), Data: data}
}

type EnrollRequest struct {
	Token     string `json:"token"`
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
	Version   string `json:"version"`
}

type EnrollResponse struct {
	AgentID   string `json:"agent_id"`
	ServerKey string `json:"server_key"`
}

// Batch is sent every interval, also when it holds no events; an empty batch
// is the heartbeat.
type Batch struct {
	AgentID       string    `json:"agent_id"`
	Seq           int64     `json:"seq"`
	SentAt        time.Time `json:"sent_at"`
	ConfigVersion int64     `json:"config_version"`
	Events        []Event   `json:"events"`
	// Metrics are the load samples taken since the last batch. They travel
	// beside the events, so a backlog of them never pushes a security event
	// out of the agent's queue, and the server keeps them out of the event
	// store. A server before v0.29.0 ignores the field.
	Metrics []Metrics `json:"metrics,omitempty"`
}

// Metrics is one sample of a host's load, taken once a minute. Rates are per
// second over the minute before TS. The detail lists (disks, interfaces,
// processes, peers) are only filled on the newest sample of a batch.
type Metrics struct {
	TS        time.Time  `json:"ts"`
	Cores     int        `json:"cores"`
	CPU       float64    `json:"cpu"` // percent busy, all cores together
	IOWait    float64    `json:"iowait"`
	Steal     float64    `json:"steal"`
	Load      [3]float64 `json:"load"`
	MemTotal  uint64     `json:"mem_total"`
	MemUsed   uint64     `json:"mem_used"` // total minus available
	MemCache  uint64     `json:"mem_cache"`
	SwapTotal uint64     `json:"swap_total"`
	SwapUsed  uint64     `json:"swap_used"`
	RX        float64    `json:"rx"` // bytes per second, physical and VPN interfaces
	TX        float64    `json:"tx"`
	DiskRead  float64    `json:"disk_read"` // bytes per second, whole disks
	DiskWrite float64    `json:"disk_write"`
	DiskPct   float64    `json:"disk_pct"` // fullest file system
	Procs     int        `json:"procs"`
	Uptime    int64      `json:"uptime"`   // seconds
	ConnIn    int        `json:"conn_in"`  // established TCP to a listening port
	ConnOut   int        `json:"conn_out"` // established TCP this host opened

	Disks  []DiskUse   `json:"disks,omitempty"`
	Ifaces []IfaceRate `json:"ifaces,omitempty"`
	Top    []ProcLoad  `json:"top,omitempty"`
	Peers  []Peer      `json:"peers,omitempty"`
}

type DiskUse struct {
	Mount string `json:"mount"`
	FS    string `json:"fs"`
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type IfaceRate struct {
	Name  string   `json:"name"`
	RX    float64  `json:"rx"`
	TX    float64  `json:"tx"`
	Addrs []string `json:"addrs,omitempty"`
}

// ProcLoad names a busy process by its program only; command lines can
// hold secrets and never leave the host this way.
type ProcLoad struct {
	PID  int     `json:"pid"`
	Comm string  `json:"comm"`
	Exe  string  `json:"exe,omitempty"`
	CPU  float64 `json:"cpu"` // percent of one core
	RSS  uint64  `json:"rss"`
}

// Peer counts established TCP connections with one remote address. Inbound
// ones are keyed by the local listening port, outbound ones by the remote
// port, so both ends of a connection between two hosts name the same port.
type Peer struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Out     bool   `json:"out"`
	N       int    `json:"n"`
	Process string `json:"process,omitempty"`
}

// BatchResponse returns the signed agent configuration whenever the agent's
// config_version is behind.
type BatchResponse struct {
	ConfigVersion int64           `json:"config_version"`
	Config        json.RawMessage `json:"config,omitempty"`
	ConfigSig     string          `json:"config_sig,omitempty"`
}

// AgentConfig is what the dashboard controls. It deliberately cannot carry
// file contents or commands: canaries name a type and a path, the agent
// generates the content itself and enforces its own local limits.
type AgentConfig struct {
	AgentID  string   `json:"agent_id"`
	Version  int64    `json:"version"`
	Canaries []Canary `json:"canaries"`
	// Actions are response actions an admin started in the dashboard. The
	// agent runs each id at most once, only before Expires, and only if its
	// own configuration allows the type.
	Actions []Action `json:"actions,omitempty"`
	// SelfTest asks the agent to leave its fixed set of harmless traces,
	// marked with the id. It carries no paths and no content.
	SelfTest *SelfTest `json:"selftest,omitempty"`
	// Snapshots ask for evidence snapshots. A request names a process id
	// at most; what is collected is fixed in the agent.
	Snapshots []SnapshotRequest `json:"snapshots,omitempty"`
	// Yara are detection rules for programs. They only ever raise findings.
	Yara *YaraRules `json:"yara,omitempty"`
	// Update asks the agent to install a release. The agent only does so
	// when its own agent.json allows it, only for a newer release, and only
	// after checking the release signature itself.
	Update *UpdateRequest `json:"update,omitempty"`
}

type UpdateRequest struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// YaraRules are the server's YARA rules, sent whole; Hash names the version.
type YaraRules struct {
	Hash   string `json:"hash"`
	Source string `json:"source"`
}

type SnapshotRequest struct {
	ID      string    `json:"id"`
	PID     int       `json:"pid,omitempty"`
	Alert   string    `json:"alert,omitempty"`
	Expires time.Time `json:"expires"`
}

type SelfTest struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
}

type Action struct {
	ID      string            `json:"id"`
	Type    string            `json:"type"` // block_ip | kill_session | kill_process | remove_key
	Params  map[string]string `json:"params"`
	Expires time.Time         `json:"expires"`
}

var ActionTypes = []string{"block_ip", "kill_session", "kill_process", "remove_key", "isolate_host", "release_host", "lock_user", "unlock_user"}

type Canary struct {
	ID     string            `json:"id"`
	Type   string            `json:"type"`
	Path   string            `json:"path"`
	Params map[string]string `json:"params,omitempty"`
	// Readable makes the file mode 0644, so a service account that was
	// broken into trips it too. The default 0600 only catches root.
	Readable bool `json:"readable,omitempty"`
}

// CanaryTypes are the only kinds an agent will ever create.
var CanaryTypes = []string{"credentials", "env", "ssh-key", "sql-dump"}

func Sign(key ed25519.PrivateKey, body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))
}

var ErrBadSignature = errors.New("bad signature")

func Verify(pub ed25519.PublicKey, body []byte, sig string) error {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, body, raw) {
		return ErrBadSignature
	}
	return nil
}

func EncodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key")
	}
	return ed25519.PublicKey(raw), nil
}

package server

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/akquisio-dev/vigil/internal/backup"
	"github.com/akquisio-dev/vigil/internal/notify"
)

type BrandConfig struct {
	// Name is shown in the window title, e.g. "Example vigil".
	Name string `json:"name"`
	// Logo is an SVG file (wordmark with the mark on the left). It is placed
	// inline, so fill="currentColor" follows light and dark mode, and the
	// collapsed sidebar shows only its left square.
	Logo string `json:"logo"`
	// Icon is an SVG file used as the browser tab icon.
	Icon string `json:"icon,omitempty"`
}

type BackupConfig struct {
	// Recipient is the public key from `vigil-server backup keygen`. The
	// secret key stays off this machine.
	Recipient string `json:"recipient"`
	// Dir holds the sealed backups (default /var/lib/vigil-backups).
	Dir string `json:"dir,omitempty"`
	// Keep is how many backups stay in Dir (default 14).
	Keep int `json:"keep,omitempty"`
	// MaxAgeHours raises server.backup_stale when the newest is older (default 36).
	MaxAgeHours int `json:"max_age_hours,omitempty"`
}

type FederationConfig struct {
	// Listen serves the feed to partners, on a VPN address only. Empty
	// serves no feed; fetching sources works without it.
	Listen string `json:"listen,omitempty"`
	// Name is how this network calls itself in its feed.
	Name string `json:"name,omitempty"`
	// Never lists addresses and networks that are never named in a feed
	// nor flagged from a source (offices, VPN exits, monitoring services).
	Never []string `json:"never,omitempty"`
}

type Config struct {
	// Listen serves the dashboard. Keep it on loopback behind a TLS proxy.
	Listen string `json:"listen"`
	// AgentListen serves the agent API, e.g. on a VPN address. Empty means
	// the agent API shares Listen.
	AgentListen string `json:"agent_listen"`
	DataDir     string `json:"data_dir"`
	PublicURL   string `json:"public_url"`
	// AgentURL is how agents reach AgentListen; shown in the enrollment
	// command.
	AgentURL string `json:"agent_url"`
	// Language of notifications: en | de.
	Language string `json:"language"`

	// CookieSecure must stay true unless the dashboard is only reached over
	// plain HTTP on loopback during development.
	CookieSecure *bool `json:"cookie_secure,omitempty"`
	// TrustProxy reads the client address from X-Forwarded-For (set by the
	// reverse proxy in front of Listen).
	TrustProxy bool `json:"trust_proxy"`

	RetentionDays  int `json:"retention_days"`
	DeadmanSeconds int `json:"deadman_seconds"`
	RecentEvents   int `json:"recent_events"`
	SessionHours   int `json:"session_hours"`

	// Backup is where `vigil-server backup` seals the server's data. The
	// server raises server.backup_stale when the newest backup there gets old.
	Backup *BackupConfig `json:"backup,omitempty"`

	// Brand replaces the vigil name and logo in the dashboard, for teams
	// that run vigil under their own name.
	Brand *BrandConfig `json:"brand,omitempty"`

	// ThreatIntel downloads public block lists (abuse.ch, Spamhaus DROP, Tor
	// exits) twice a day and matches outbound connections against them.
	ThreatIntel bool `json:"threat_intel,omitempty"`
	// VulnLookup matches the package lists of Debian and Ubuntu hosts with
	// the distributions' vulnerability data (OSV) and CISA's catalogue of
	// exploited vulnerabilities. The server downloads the complete data of
	// each release in use once a week (about 150 MB for an Ubuntu LTS
	// release) and the changes daily; nothing is sent.
	VulnLookup bool `json:"vuln_lookup,omitempty"`
	// HashIntel matches the SHA-256 of programs the agents report against
	// abuse.ch MalwareBazaar and ThreatFox (the full list once a week, about
	// 45 MB, the newest every six hours). Only downloads; nothing is sent.
	HashIntel bool `json:"hash_intel,omitempty"`
	// AbuseCHKeyFile holds a free abuse.ch Auth-Key. ThreatFox (threat_intel,
	// hash_intel) and MalwareBazaar (hash_intel) need it since October 2026.
	AbuseCHKeyFile string `json:"abusech_key_file,omitempty"`
	// YaraDir holds YARA rules (*.yar, *.yara) the agents scan suspicious
	// programs with. A subset of the language is supported, see the docs.
	YaraDir string `json:"yara_dir,omitempty"`
	// SigmaDir holds Sigma rules (*.yml, also in subdirectories) for Linux
	// process, network and file events.
	SigmaDir string `json:"sigma_dir,omitempty"`
	// Forward sends events and alerts to syslog, HTTP or a file.
	Forward []ForwardConfig `json:"forward,omitempty"`
	// GeoIP downloads the free DB-IP Lite country and AS databases (CC BY
	// 4.0, about 12 MB) once a month to show where attacking addresses come
	// from. Lookups stay on the server.
	GeoIP bool `json:"geoip,omitempty"`
	// MapHome is where the hosts stand, as [latitude, longitude], for the
	// live view of the attack map. Without it the map shows no arcs.
	MapHome *[2]float64 `json:"map_home,omitempty"`
	// Federation exchanges attack data with allied networks, see the docs.
	Federation *FederationConfig `json:"federation,omitempty"`
	// FourEyes lists response action types that a second admin must approve
	// (with a fresh TOTP code) before they reach the agent; "*" means all.
	FourEyes []string `json:"four_eyes,omitempty"`
	// Playbooks start response actions on their own when an alert of one
	// of their rules is raised. See the docs before enabling any.
	Playbooks []Playbook `json:"playbooks,omitempty"`
	// RulesDir holds custom rules (*.json), loaded at start.
	RulesDir string `json:"rules_dir,omitempty"`

	Notifiers []NotifierConfig `json:"notifiers"`
	// HeartbeatURL is fetched every minute while the server is healthy, so
	// an outside service (healthchecks.io, Uptime Kuma push, Better Stack)
	// notices when the server is down, hung, or its event log is broken.
	HeartbeatURL string `json:"heartbeat_url,omitempty"`
	// AnchorDaily posts the head of the event chain to all notifiers once a
	// day, leaving a copy outside this machine that later tampering cannot
	// match.
	AnchorDaily bool `json:"anchor_daily"`
	// SelfTestDays runs a self test on every agent this often (default 7)
	// and sends the result to all notifiers. -1 turns the schedule off.
	SelfTestDays int `json:"selftest_days,omitempty"`
	// NotifyGroupMinutes collects the follow-up alerts of an incident into
	// one message this often (default 10). The first alert and every more
	// severe one are sent at once. -1 sends every alert on its own.
	NotifyGroupMinutes int `json:"notify_group_minutes,omitempty"`
	// SummaryTime sends a daily summary of the fleet at this local time
	// ("07:30") to every notifier, whatever its min_severity. Empty is off.
	SummaryTime string `json:"summary_time,omitempty"`
}

// NotifierConfig is one notification channel, see notify.Config.
type NotifierConfig = notify.Config

func (c *Config) cookieSecure() bool { return c.CookieSecure == nil || *c.CookieSecure }
func (c *Config) deadman() time.Duration {
	return time.Duration(c.DeadmanSeconds) * time.Second
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8470"
	}
	if b := c.Backup; b != nil {
		if _, err := backup.ParsePublic(b.Recipient); err != nil {
			return nil, fmt.Errorf("backup.recipient: %w", err)
		}
		if b.Dir == "" {
			b.Dir = "/var/lib/vigil-backups"
		}
		if b.Keep <= 0 {
			b.Keep = 14
		}
		if b.MaxAgeHours <= 0 {
			b.MaxAgeHours = 36
		}
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/vigil"
	}
	if c.Language != "de" {
		c.Language = "en"
	}
	if c.RetentionDays <= 0 {
		c.RetentionDays = 90
	}
	if c.DeadmanSeconds <= 0 {
		c.DeadmanSeconds = 120
	}
	if c.RecentEvents <= 0 {
		c.RecentEvents = 20000
	}
	if c.SelfTestDays == 0 {
		c.SelfTestDays = 7
	}
	if c.SessionHours <= 0 {
		c.SessionHours = 12
	}
	if c.SummaryTime != "" {
		if _, _, err := summaryAt(c.SummaryTime); err != nil {
			return nil, err
		}
	}
	names := map[string]bool{}
	for i := range c.Notifiers {
		n := &c.Notifiers[i]
		if n.Name == "" {
			n.Name = fmt.Sprintf("%s-%d", n.Type, i+1)
		}
		if names[n.Name] {
			return nil, fmt.Errorf("notifier name %q is used twice", n.Name)
		}
		names[n.Name] = true
		if err := n.Check(); err != nil {
			return nil, fmt.Errorf("notifier %q: %w", n.Name, err)
		}
	}
	return &c, nil
}

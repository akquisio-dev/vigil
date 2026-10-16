package server

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
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

	// Brand replaces the vigil name and logo in the dashboard, for teams
	// that run vigil under their own name.
	Brand *BrandConfig `json:"brand,omitempty"`

	// RulesDir holds custom rules (*.json), loaded at start.
	RulesDir string `json:"rules_dir,omitempty"`

	Notifiers []NotifierConfig `json:"notifiers"`
	// HeartbeatURL is fetched every minute so an outside service notices
	// when the server itself is down (healthchecks.io style).
	HeartbeatURL string `json:"heartbeat_url,omitempty"`
	// AnchorDaily posts the head of the event chain to all notifiers once a
	// day, leaving a copy outside this machine that later tampering cannot
	// match.
	AnchorDaily bool `json:"anchor_daily"`
}

type NotifierConfig struct {
	Type        string `json:"type"` // discord | webhook | smtp
	Name        string `json:"name"`
	MinSeverity string `json:"min_severity"`

	URL string `json:"url,omitempty"` // discord, webhook

	SMTPHost string   `json:"smtp_host,omitempty"`
	SMTPPort int      `json:"smtp_port,omitempty"`
	SMTPUser string   `json:"smtp_user,omitempty"`
	SMTPPass string   `json:"smtp_pass,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
}

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
	if c.SessionHours <= 0 {
		c.SessionHours = 12
	}
	for i, n := range c.Notifiers {
		if n.MinSeverity == "" {
			c.Notifiers[i].MinSeverity = "high"
		}
		if _, ok := severityRank[c.Notifiers[i].MinSeverity]; !ok {
			return nil, fmt.Errorf("notifier %q: unknown min_severity %q", n.Name, n.MinSeverity)
		}
	}
	return &c, nil
}

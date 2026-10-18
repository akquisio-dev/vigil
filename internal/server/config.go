package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
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
}

type NotifierConfig struct {
	Type        string `json:"type"` // discord | slack | ntfy | telegram | webhook | smtp
	Name        string `json:"name"`
	MinSeverity string `json:"min_severity"`

	URL string `json:"url,omitempty"` // discord, slack, ntfy (topic URL), webhook

	// Mention is pinged in Discord for alerts of MentionMinSeverity and
	// above (default critical): "<@&ROLE_ID>", "<@USER_ID>", "@here" or
	// "@everyone".
	Mention            string `json:"mention,omitempty"`
	MentionMinSeverity string `json:"mention_min_severity,omitempty"`

	// Token is the ntfy access token or the Telegram bot token.
	Token  string `json:"token,omitempty"`
	ChatID string `json:"chat_id,omitempty"` // telegram

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
	if c.SelfTestDays == 0 {
		c.SelfTestDays = 7
	}
	if c.SessionHours <= 0 {
		c.SessionHours = 12
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
		if err := n.check(); err != nil {
			return nil, fmt.Errorf("notifier %q: %w", n.Name, err)
		}
	}
	return &c, nil
}

var (
	discordMention = regexp.MustCompile(`^(<@&?[0-9]{1,20}>|@here|@everyone)$`)
	telegramToken  = regexp.MustCompile(`^[0-9]{1,20}:[A-Za-z0-9_-]{20,}$`)
)

func httpURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("url must be an http(s) address")
	}
	return nil
}

// check fills defaults and refuses incomplete notifiers at start, so a typo
// is found at install time and not when the first alert is lost.
func (n *NotifierConfig) check() error {
	if n.MinSeverity == "" {
		n.MinSeverity = "high"
	}
	if _, ok := severityRank[n.MinSeverity]; !ok {
		return fmt.Errorf("unknown min_severity %q", n.MinSeverity)
	}
	switch n.Type {
	case "discord", "slack", "webhook":
		if err := httpURL(n.URL); err != nil {
			return err
		}
	case "ntfy":
		if err := httpURL(n.URL); err != nil {
			return err
		}
		u, _ := url.Parse(n.URL)
		if t := strings.Trim(u.Path, "/"); t == "" || strings.Contains(t, "/") {
			return errors.New("url must be the topic URL, e.g. https://ntfy.sh/your-topic")
		}
	case "telegram":
		if !telegramToken.MatchString(n.Token) || n.ChatID == "" {
			return errors.New("telegram needs token (from @BotFather) and chat_id")
		}
	case "smtp":
		if n.SMTPHost == "" || n.From == "" || len(n.To) == 0 {
			return errors.New("smtp needs smtp_host, from and to")
		}
	default:
		return fmt.Errorf("unknown type %q", n.Type)
	}
	if n.Mention != "" {
		if n.Type != "discord" || !discordMention.MatchString(n.Mention) {
			return errors.New(`mention is for discord: "<@&ROLE_ID>", "<@USER_ID>", "@here" or "@everyone"`)
		}
		if n.MentionMinSeverity == "" {
			n.MentionMinSeverity = "critical"
		}
		if _, ok := severityRank[n.MentionMinSeverity]; !ok {
			return fmt.Errorf("unknown mention_min_severity %q", n.MentionMinSeverity)
		}
	}
	return nil
}

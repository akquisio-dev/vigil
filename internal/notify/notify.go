// Package notify delivers vigil messages to chat, push and mail services.
// The server uses it for alerts, the agent for its own fallback notice when
// the server cannot be reached.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SeverityRank orders the alert severities.
var SeverityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Config is one notification channel.
type Config struct {
	Type        string `json:"type"` // discord | slack | ntfy | telegram | webhook | smtp
	Name        string `json:"name"`
	MinSeverity string `json:"min_severity"`

	URL string `json:"url,omitempty"` // discord, slack, ntfy (topic URL), webhook

	// Mention is pinged in Discord for alerts of MentionMinSeverity and
	// above (default critical): "<@&ROLE_ID>", "<@USER_ID>", "@here" or
	// "@everyone".
	Mention            string `json:"mention,omitempty"`
	MentionMinSeverity string `json:"mention_min_severity,omitempty"`

	// Summary false leaves this notifier out of the daily summary.
	Summary *bool `json:"summary,omitempty"`

	// Groups limits the notifier to alerts of hosts in one of these host
	// groups (tags); it then gets no daily summary and nothing about the
	// server itself, which concern the whole network.
	Groups []string `json:"groups,omitempty"`

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

var severityColor = map[string]int{"info": 0x8a8f98, "low": 0x4a90d9, "medium": 0xe0a100, "high": 0xe0622b, "critical": 0xc8102e}

// ntfy priorities: 1 min, 3 default, 5 urgent (bypasses do-not-disturb on
// most phones).
var ntfyPriority = map[string]int{"info": 2, "low": 2, "medium": 3, "high": 4, "critical": 5}

// Message is what a notifier sends: an alert layout or a plain Text.
type Message struct {
	Severity  string
	Title     string
	Host      string
	Technique string
	Link      string
	Text      string // used instead of the alert layout, e.g. chain anchors
	// Groups are the groups of the alert's host, for notifiers with Groups.
	Groups []string
}

// Plain renders a Message for channels without rich layout.
func (m Message) Plain() string {
	if m.Text != "" {
		return m.Text
	}
	var b strings.Builder
	b.WriteString(strings.ToUpper(m.Severity) + ": " + m.Title)
	if m.Host != "" {
		b.WriteString("\nHost: " + m.Host)
	}
	if m.Technique != "" {
		b.WriteString("\nATT&CK: " + m.Technique)
	}
	if m.Link != "" {
		b.WriteString("\n" + m.Link)
	}
	return b.String()
}

func Deliver(n Config, m Message) error {
	switch n.Type {
	case "discord":
		return deliverDiscord(n, m)
	case "slack":
		return deliverSlack(n, m)
	case "ntfy":
		return deliverNtfy(n, m)
	case "telegram":
		return deliverTelegram(n, m)
	case "webhook":
		return PostJSON(n.URL, map[string]any{
			"severity": m.Severity, "title": m.Title, "host": m.Host,
			"technique": m.Technique, "link": m.Link, "text": m.Text,
		}, nil)
	case "smtp":
		return deliverSMTP(n, m)
	}
	return fmt.Errorf("unknown notifier type %q", n.Type)
}

func deliverDiscord(n Config, m Message) error {
	allowed := map[string]any{"parse": []string{}}
	mention := ""
	if n.Mention != "" && SeverityRank[m.Severity] >= SeverityRank[n.MentionMinSeverity] && m.Text == "" {
		mention = n.Mention
		id := strings.Trim(n.Mention, "<@&>")
		switch {
		case n.Mention == "@everyone" || n.Mention == "@here":
			allowed["parse"] = []string{"everyone"}
		case strings.HasPrefix(n.Mention, "<@&"):
			allowed["roles"] = []string{id}
		default:
			allowed["users"] = []string{id}
		}
	}
	if m.Text != "" {
		return PostJSON(n.URL, map[string]any{"content": Truncate(m.Text, 1900), "allowed_mentions": allowed}, nil)
	}
	var fields []map[string]any
	if m.Host != "" {
		fields = append(fields, map[string]any{"name": "Host", "value": m.Host, "inline": true})
	}
	fields = append(fields, map[string]any{"name": "Severity", "value": m.Severity, "inline": true})
	if m.Technique != "" {
		fields = append(fields, map[string]any{"name": "ATT&CK", "value": m.Technique, "inline": true})
	}
	embed := map[string]any{"title": Truncate(m.Title, 250), "color": severityColor[m.Severity], "fields": fields,
		"timestamp": time.Now().UTC().Format(time.RFC3339)}
	if m.Link != "" {
		embed["url"] = m.Link
	}
	body := map[string]any{"username": "vigil", "embeds": []any{embed}, "allowed_mentions": allowed}
	if mention != "" {
		body["content"] = mention
	}
	return PostJSON(n.URL, body, nil)
}

// slackEscape keeps agent-controlled text from forming links or mentions
// (Slack, Mattermost and Rocket.Chat read <...> as markup).
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func deliverSlack(n Config, m Message) error {
	text := slackEscape.Replace(m.Plain())
	if m.Text == "" {
		text = "*" + strings.ToUpper(m.Severity) + "*: " + slackEscape.Replace(m.Title)
		if m.Host != "" {
			text += "\nHost: " + slackEscape.Replace(m.Host)
		}
		if m.Technique != "" {
			text += "\nATT&amp;CK: " + m.Technique
		}
		if m.Link != "" {
			text += "\n<" + m.Link + "|Open in vigil>"
		}
	}
	return PostJSON(n.URL, map[string]any{"text": Truncate(text, 3000), "username": "vigil"}, nil)
}

// deliverNtfy uses ntfy's JSON publishing, so titles with any characters
// never end up in HTTP headers. URL is the full topic URL.
func deliverNtfy(n Config, m Message) error {
	u, err := url.Parse(n.URL)
	if err != nil {
		return errors.New("bad ntfy url")
	}
	topic := strings.Trim(u.Path, "/")
	u.Path = "/"
	msg := map[string]any{"topic": topic, "priority": ntfyPriority[m.Severity], "tags": []string{"vigil", m.Severity}}
	if m.Text != "" {
		msg["title"] = "vigil"
		msg["Message"] = Truncate(m.Text, 3500)
	} else {
		msg["title"] = Truncate(m.Title, 250)
		body := strings.ToUpper(m.Severity)
		if m.Host != "" {
			body += " on " + m.Host
		}
		if m.Technique != "" {
			body += " (" + m.Technique + ")"
		}
		msg["Message"] = body
		if m.Link != "" {
			msg["click"] = m.Link
		}
	}
	var hdr map[string]string
	if n.Token != "" {
		hdr = map[string]string{"Authorization": "Bearer " + n.Token}
	}
	return PostJSON(u.String(), msg, hdr)
}

func deliverTelegram(n Config, m Message) error {
	api := "https://api.telegram.org/bot" + n.Token + "/sendMessage"
	return PostJSON(api, map[string]any{"chat_id": n.ChatID, "text": Truncate(m.Plain(), 3500), "disable_web_page_preview": true}, nil)
}

// RetryAfter carries a rate limit answer (HTTP 429) so the retry waits as
// long as the service asks.
type RetryAfter struct {
	Status string
	Wait   time.Duration
}

func (e *RetryAfter) Error() string { return "status " + e.Status }

func PostJSON(target string, v any, hdr map[string]string) error {
	body, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return errors.New("invalid notifier url")
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return Redact(err)
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	res.Body.Close()
	if res.StatusCode == http.StatusTooManyRequests {
		secs, _ := strconv.ParseFloat(res.Header.Get("Retry-After"), 64)
		return &RetryAfter{Status: res.Status, Wait: time.Duration(secs * float64(time.Second))}
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("status %s", res.Status)
	}
	return nil
}

// Redact strips the request URL from transport errors. Webhook URLs carry
// their secret in the path (Discord, Slack, Telegram bot tokens, ntfy
// topics), and these errors end up in the journal and the dashboard.
func Redact(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		host := ""
		if u, perr := url.Parse(ue.URL); perr == nil {
			host = u.Hostname()
		}
		inner := ue.Err.Error()
		if ue.URL != "" {
			inner = strings.ReplaceAll(inner, ue.URL, "<url>")
		}
		if host == "" {
			return errors.New(inner)
		}
		return fmt.Errorf("%s: %s", host, inner)
	}
	return errors.New("invalid notifier url")
}

func deliverSMTP(n Config, m Message) error {
	subject := "[vigil] " + strings.ToUpper(m.Severity) + ": " + m.Title
	body := m.Text
	if body == "" {
		body = m.Title + "\n"
		if m.Host != "" {
			body += "\nHost: " + m.Host
		}
		if m.Technique != "" {
			body += "\nATT&CK: " + m.Technique
		}
		if m.Link != "" {
			body += "\n\n" + m.Link
		}
		body += "\n"
	} else {
		subject = "[vigil] " + firstLine(m.Text)
	}
	msg := "From: " + n.From + "\r\nTo: " + strings.Join(n.To, ", ") + "\r\nSubject: " + mimeHeader(Truncate(subject, 200)) +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" + strings.ReplaceAll(body, "\n", "\r\n")

	port := n.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(n.SMTPHost, strconv.Itoa(port))
	var auth smtp.Auth
	if n.SMTPUser != "" {
		auth = smtp.PlainAuth("", n.SMTPUser, n.SMTPPass, n.SMTPHost)
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: n.SMTPHost})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	// A mail server that accepts the connection and then stalls must not
	// hold a delivery (or the dashboard's test request) forever.
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, n.SMTPHost)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: n.SMTPHost}); err != nil {
				return err
			}
		}
	}
	// PlainAuth refuses to send credentials over an unencrypted connection
	// to a remote host, so a server without STARTTLS fails here.
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(n.From); err != nil {
		return err
	}
	for _, to := range n.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func mimeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?utf-8?B?" + b64(s) + "?="
		}
	}
	return s
}

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

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

// Check fills defaults and refuses incomplete notifiers at start, so a typo
// is found at install time and not when the first alert is lost.
func (n *Config) Check() error {
	if n.MinSeverity == "" {
		n.MinSeverity = "high"
	}
	if _, ok := SeverityRank[n.MinSeverity]; !ok {
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
		if _, ok := SeverityRank[n.MentionMinSeverity]; !ok {
			return fmt.Errorf("unknown mention_min_severity %q", n.MentionMinSeverity)
		}
	}
	return nil
}

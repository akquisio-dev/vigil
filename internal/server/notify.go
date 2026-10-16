package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var severityColor = map[string]int{"info": 0x8a8f98, "low": 0x4a90d9, "medium": 0xe0a100, "high": 0xe0622b, "critical": 0xc8102e}

// ntfy priorities: 1 min, 3 default, 5 urgent (bypasses do-not-disturb on
// most phones).
var ntfyPriority = map[string]int{"info": 2, "low": 2, "medium": 3, "high": 4, "critical": 5}

type message struct {
	Severity  string
	Title     string
	Host      string
	Technique string
	Link      string
	Text      string // used instead of the alert layout, e.g. chain anchors
}

// plain renders a message for channels without rich layout.
func (m message) plain() string {
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

func (s *Server) alertMessage(al *Alert) message {
	host := ""
	if a := s.state.Agents[al.Agent]; a != nil {
		host = a.Name
	}
	link := ""
	if s.cfg.PublicURL != "" {
		link = strings.TrimRight(s.cfg.PublicURL, "/") + "/#/alerts/" + al.ID
	}
	return message{
		Severity: al.Severity, Title: renderTitle(al.Rule, decodeParams(al.Detail), s.cfg.Language),
		Host: host, Technique: al.Technique, Link: link,
	}
}

// NotifierStatus is what the dashboard shows per notifier. Errors never
// contain the notifier URL or credentials, see redact.
type NotifierStatus struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	MinSeverity string    `json:"min_severity"`
	LastOK      time.Time `json:"last_ok,omitempty"`
	LastFail    time.Time `json:"last_fail,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures"` // messages lost in a row
}

type notifierHealth struct {
	mu sync.Mutex
	m  map[string]*NotifierStatus
}

func (s *Server) notifierStatus() []NotifierStatus {
	s.nh.mu.Lock()
	defer s.nh.mu.Unlock()
	out := make([]NotifierStatus, 0, len(s.cfg.Notifiers))
	for _, n := range s.cfg.Notifiers {
		st := NotifierStatus{Name: n.Name, Type: n.Type, MinSeverity: n.MinSeverity}
		if p := s.nh.m[n.Name]; p != nil {
			st = *p
		}
		out = append(out, st)
	}
	return out
}

// notify delivers in the background; a slow mail server must never hold up
// event ingestion. It may be called with s.mu held.
func (s *Server) notify(m message, force bool) { s.notifyExcept(m, force, "") }

func (s *Server) notifyExcept(m message, force bool, skip string) {
	for _, n := range s.cfg.Notifiers {
		if n.Name == skip || !force && severityRank[m.Severity] < severityRank[n.MinSeverity] {
			continue
		}
		go func(n NotifierConfig) {
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				if err = deliver(n, m); err == nil {
					break
				}
				wait := time.Duration(attempt+1) * 5 * time.Second
				var ra *retryAfter
				if errors.As(err, &ra) && ra.wait > wait && ra.wait <= time.Minute {
					wait = ra.wait
				}
				time.Sleep(wait)
			}
			s.noteDelivery(n, err)
		}(n)
	}
}

// noteDelivery tracks each notifier's health. A lost message raises
// notify.failed, sent through the other notifiers only, so a broken channel
// cannot feed on itself; the next successful delivery resolves it. It takes
// s.mu, so it must not be called with s.mu held.
func (s *Server) noteDelivery(n NotifierConfig, err error) {
	now := time.Now().UTC()
	s.nh.mu.Lock()
	if s.nh.m == nil {
		s.nh.m = map[string]*NotifierStatus{}
	}
	st := s.nh.m[n.Name]
	if st == nil {
		st = &NotifierStatus{Name: n.Name, Type: n.Type, MinSeverity: n.MinSeverity}
		s.nh.m[n.Name] = st
	}
	failedBefore := st.Failures > 0
	if err == nil {
		st.LastOK, st.Failures = now, 0
	} else {
		st.LastFail, st.LastError = now, clip(err.Error(), 300)
		st.Failures++
	}
	s.nh.mu.Unlock()

	key := "notify.failed|" + n.Name + "|"
	if err == nil {
		if failedBefore {
			s.mu.Lock()
			s.resolve(key, "system")
			s.saveLocked()
			s.mu.Unlock()
		}
		return
	}
	log.Printf("notify %s (%s): %v", n.Name, n.Type, err)
	s.mu.Lock()
	fresh := s.raise([]finding{{Rule: "notify.failed", Key: key, Params: map[string]string{"notifier": n.Name, "type": n.Type, "error": clip(err.Error(), 200)}}}, "", 0)
	s.saveLocked()
	for _, al := range fresh {
		s.notifyExcept(s.alertMessage(al), false, n.Name)
	}
	s.mu.Unlock()
}

// TestNotifiers sends one message to every notifier (or the one named) and
// waits for the results. Used by `vigil-server notify test` and the
// dashboard.
func TestNotifiers(cfg *Config, name, text string) map[string]error {
	out := map[string]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range cfg.Notifiers {
		if name != "" && n.Name != name {
			continue
		}
		wg.Add(1)
		go func(n NotifierConfig) {
			defer wg.Done()
			err := deliver(n, message{Severity: "info", Text: text})
			mu.Lock()
			out[n.Name] = err
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out
}

func deliver(n NotifierConfig, m message) error {
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
		return postJSON(n.URL, map[string]any{
			"severity": m.Severity, "title": m.Title, "host": m.Host,
			"technique": m.Technique, "link": m.Link, "text": m.Text,
		}, nil)
	case "smtp":
		return deliverSMTP(n, m)
	}
	return fmt.Errorf("unknown notifier type %q", n.Type)
}

func deliverDiscord(n NotifierConfig, m message) error {
	allowed := map[string]any{"parse": []string{}}
	mention := ""
	if n.Mention != "" && severityRank[m.Severity] >= severityRank[n.MentionMinSeverity] && m.Text == "" {
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
		return postJSON(n.URL, map[string]any{"content": truncate(m.Text, 1900), "allowed_mentions": allowed}, nil)
	}
	var fields []map[string]any
	if m.Host != "" {
		fields = append(fields, map[string]any{"name": "Host", "value": m.Host, "inline": true})
	}
	fields = append(fields, map[string]any{"name": "Severity", "value": m.Severity, "inline": true})
	if m.Technique != "" {
		fields = append(fields, map[string]any{"name": "ATT&CK", "value": m.Technique, "inline": true})
	}
	embed := map[string]any{"title": truncate(m.Title, 250), "color": severityColor[m.Severity], "fields": fields,
		"timestamp": time.Now().UTC().Format(time.RFC3339)}
	if m.Link != "" {
		embed["url"] = m.Link
	}
	body := map[string]any{"username": "vigil", "embeds": []any{embed}, "allowed_mentions": allowed}
	if mention != "" {
		body["content"] = mention
	}
	return postJSON(n.URL, body, nil)
}

// slackEscape keeps agent-controlled text from forming links or mentions
// (Slack, Mattermost and Rocket.Chat read <...> as markup).
var slackEscape = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func deliverSlack(n NotifierConfig, m message) error {
	text := slackEscape.Replace(m.plain())
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
	return postJSON(n.URL, map[string]any{"text": truncate(text, 3000), "username": "vigil"}, nil)
}

// deliverNtfy uses ntfy's JSON publishing, so titles with any characters
// never end up in HTTP headers. URL is the full topic URL.
func deliverNtfy(n NotifierConfig, m message) error {
	u, err := url.Parse(n.URL)
	if err != nil {
		return errors.New("bad ntfy url")
	}
	topic := strings.Trim(u.Path, "/")
	u.Path = "/"
	msg := map[string]any{"topic": topic, "priority": ntfyPriority[m.Severity], "tags": []string{"vigil", m.Severity}}
	if m.Text != "" {
		msg["title"] = "vigil"
		msg["message"] = truncate(m.Text, 3500)
	} else {
		msg["title"] = truncate(m.Title, 250)
		body := strings.ToUpper(m.Severity)
		if m.Host != "" {
			body += " on " + m.Host
		}
		if m.Technique != "" {
			body += " (" + m.Technique + ")"
		}
		msg["message"] = body
		if m.Link != "" {
			msg["click"] = m.Link
		}
	}
	var hdr map[string]string
	if n.Token != "" {
		hdr = map[string]string{"Authorization": "Bearer " + n.Token}
	}
	return postJSON(u.String(), msg, hdr)
}

func deliverTelegram(n NotifierConfig, m message) error {
	api := "https://api.telegram.org/bot" + n.Token + "/sendMessage"
	return postJSON(api, map[string]any{"chat_id": n.ChatID, "text": truncate(m.plain(), 3500), "disable_web_page_preview": true}, nil)
}

// retryAfter carries a rate limit answer (HTTP 429) so the retry waits as
// long as the service asks.
type retryAfter struct {
	status string
	wait   time.Duration
}

func (e *retryAfter) Error() string { return "status " + e.status }

func postJSON(target string, v any, hdr map[string]string) error {
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
		return redact(err)
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	res.Body.Close()
	if res.StatusCode == http.StatusTooManyRequests {
		secs, _ := strconv.ParseFloat(res.Header.Get("Retry-After"), 64)
		return &retryAfter{status: res.Status, wait: time.Duration(secs * float64(time.Second))}
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("status %s", res.Status)
	}
	return nil
}

// redact strips the request URL from transport errors. Webhook URLs carry
// their secret in the path (Discord, Slack, Telegram bot tokens, ntfy
// topics), and these errors end up in the journal and the dashboard.
func redact(err error) error {
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

func deliverSMTP(n NotifierConfig, m message) error {
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
	msg := "From: " + n.From + "\r\nTo: " + strings.Join(n.To, ", ") + "\r\nSubject: " + mimeHeader(truncate(subject, 200)) +
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
	if port != 465 {
		// SendMail upgrades with STARTTLS and PlainAuth refuses to send
		// credentials over an unencrypted remote connection.
		return smtp.SendMail(addr, auth, n.From, n.To, []byte(msg))
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, &tls.Config{ServerName: n.SMTPHost})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, n.SMTPHost)
	if err != nil {
		return err
	}
	defer c.Close()
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

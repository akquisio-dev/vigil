package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

var severityColor = map[string]int{"info": 0x8a8f98, "low": 0x4a90d9, "medium": 0xe0a100, "high": 0xe0622b, "critical": 0xc8102e}

type message struct {
	Severity  string
	Title     string
	Host      string
	Technique string
	Link      string
	Text      string // used instead of the alert layout, e.g. chain anchors
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

// notify delivers in the background; a slow mail server must never hold up
// event ingestion.
func (s *Server) notify(m message, force bool) {
	for _, n := range s.cfg.Notifiers {
		if !force && severityRank[m.Severity] < severityRank[n.MinSeverity] {
			continue
		}
		go func(n NotifierConfig) {
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				if err = deliver(n, m); err == nil {
					return
				}
				time.Sleep(time.Duration(attempt+1) * 5 * time.Second)
			}
			log.Printf("notify %s (%s): %v", n.Name, n.Type, err)
		}(n)
	}
}

func deliver(n NotifierConfig, m message) error {
	switch n.Type {
	case "discord":
		return deliverDiscord(n, m)
	case "webhook":
		return postJSON(n.URL, map[string]any{
			"severity": m.Severity, "title": m.Title, "host": m.Host,
			"technique": m.Technique, "link": m.Link, "text": m.Text,
		})
	case "smtp":
		return deliverSMTP(n, m)
	}
	return fmt.Errorf("unknown notifier type %q", n.Type)
}

func deliverDiscord(n NotifierConfig, m message) error {
	if m.Text != "" {
		return postJSON(n.URL, map[string]any{"content": m.Text, "allowed_mentions": map[string]any{"parse": []string{}}})
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
	return postJSON(n.URL, map[string]any{"username": "vigil", "embeds": []any{embed}, "allowed_mentions": map[string]any{"parse": []string{}}})
}

func postJSON(url string, v any) error {
	body, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("status %s", res.Status)
	}
	return nil
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

package server

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

type ruleDef struct {
	Severity  string
	Technique string // MITRE ATT&CK
	En, De    string
}

// rules is the full catalogue. Titles are templates over the alert params.
var rules = map[string]ruleDef{
	"ssh.password_login": {"high", "T1078", "Password login as {user} from {ip}", "Passwort-Anmeldung als {user} von {ip}"},
	"ssh.new_source":     {"medium", "T1078", "{user} logged in from new address {ip}", "{user} hat sich von neuer Adresse {ip} angemeldet"},
	"ssh.unknown_key":    {"high", "T1098.004", "Login as {user} with a key not in authorized_keys ({fingerprint})", "Anmeldung als {user} mit Schlüssel außerhalb von authorized_keys ({fingerprint})"},
	"ssh.bruteforce":     {"low", "T1110", "{count} failed SSH logins from {ip}", "{count} fehlgeschlagene SSH-Anmeldungen von {ip}"},
	"ssh.key_added":      {"high", "T1098.004", "SSH key added to {file}: {comment}", "SSH-Schlüssel hinzugefügt in {file}: {comment}"},
	"ssh.key_removed":    {"low", "", "SSH key removed from {file}: {comment}", "SSH-Schlüssel entfernt aus {file}: {comment}"},

	"user.added":   {"high", "T1136.001", "New account {user} (uid {uid})", "Neues Konto {user} (uid {uid})"},
	"user.root":    {"critical", "T1078.003", "Account {user} now has uid 0", "Konto {user} hat jetzt uid 0"},
	"user.removed": {"low", "T1531", "Account {user} removed", "Konto {user} entfernt"},

	"file.preload":    {"critical", "T1574.006", "{path}: {change}", "{path}: {change}"},
	"file.sudo":       {"high", "T1548.003", "{path}: {change}", "{path}: {change}"},
	"file.pam":        {"high", "T1556.003", "{path}: {change}", "{path}: {change}"},
	"file.cron":       {"high", "T1053.003", "{path}: {change}", "{path}: {change}"},
	"file.sshd":       {"medium", "T1098", "{path}: {change}", "{path}: {change}"},
	"file.systemd":    {"medium", "T1543.002", "{path}: {change}", "{path}: {change}"},
	"file.shell_init": {"medium", "T1546.004", "{path}: {change}", "{path}: {change}"},
	"file.accounts":   {"medium", "T1098", "{path}: {change}", "{path}: {change}"},
	"file.other":      {"low", "", "{path}: {change}", "{path}: {change}"},

	"port.docker": {"high", "", "Docker publishes {proto}/{port} on {addr}, past the host firewall", "Docker veröffentlicht {proto}/{port} auf {addr}, an der Host-Firewall vorbei"},
	"port.public": {"medium", "", "New port {proto}/{port} on {addr} ({process})", "Neuer Port {proto}/{port} auf {addr} ({process})"},
	"port.local":  {"low", "", "New local port {proto}/{port} ({process})", "Neuer lokaler Port {proto}/{port} ({process})"},

	"canary.opened":        {"critical", "T1552.001", "Canary {path} opened by {exe} (uid {uid})", "Köder {path} geöffnet von {exe} (uid {uid})"},
	"canary.tampered":      {"high", "T1070.004", "Canary {path}: {problem}", "Köder {path}: {problem}"},
	"canary.remove_failed": {"medium", "", "Canary {path} could not be removed: {error}", "Köder {path} ließ sich nicht entfernen: {error}"},
	"canary.overflow":      {"medium", "", "Canary event queue overflowed on {host}", "Köder-Warteschlange auf {host} übergelaufen"},

	"agent.silent":          {"high", "T1562.001", "Agent {host} silent", "Agent {host} meldet sich nicht"},
	"agent.stopped":         {"high", "T1562.001", "Agent {host} was stopped", "Agent {host} wurde beendet"},
	"agent.restarted":       {"high", "T1562.001", "Agent {host} restarted after {gap} without monitoring", "Agent {host} neu gestartet nach {gap} ohne Überwachung"},
	"agent.config_rejected": {"high", "T1557", "Agent {host} rejected a configuration ({reason})", "Agent {host} hat eine Konfiguration abgelehnt ({reason})"},
	"log.spoofed":           {"high", "T1070", "Fake {identifier} log entry written by {comm} (uid {uid})", "Gefälschter {identifier}-Logeintrag von {comm} (uid {uid})"},
	"agent.dropped":         {"low", "", "Agent {host} dropped {count} events", "Agent {host} hat {count} Ereignisse verworfen"},
	"agent.forged":          {"high", "T1557", "Request with invalid signature for agent {agent} from {ip}", "Anfrage mit ungültiger Signatur für Agent {agent} von {ip}"},
	"chain.broken":          {"critical", "T1565.001", "Event chain broken: {error}", "Ereigniskette gebrochen: {error}"},
}

var words = map[string]map[string]string{
	"de": {
		"added": "neu angelegt", "changed": "geändert", "removed": "gelöscht",
		"missing": "gelöscht", "replaced": "ersetzt", "modified": "verändert",
		"signature": "Signatur", "content": "Inhalt",
	},
}

func renderTitle(rule string, params map[string]string, lang string) string {
	def, ok := lookupRule(rule)
	if !ok {
		return rule
	}
	tpl := def.En
	if lang == "de" {
		tpl = def.De
	}
	for k, v := range params {
		if w, ok := words[lang][v]; ok && (k == "change" || k == "problem" || k == "reason") {
			v = w
		}
		tpl = strings.ReplaceAll(tpl, "{"+k+"}", v)
	}
	// Placeholders without a value disappear together with "()".
	for strings.Contains(tpl, "{") {
		i := strings.Index(tpl, "{")
		j := strings.Index(tpl[i:], "}")
		if j < 0 {
			break
		}
		tpl = tpl[:i] + tpl[i+j+1:]
	}
	return strings.TrimSpace(strings.ReplaceAll(tpl, " ()", ""))
}

type finding struct {
	Rule   string
	Key    string
	Params map[string]string
}

func str(d map[string]any, k string) string {
	switch v := d[k].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%g", v)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func num(d map[string]any, k string) float64 {
	v, _ := d[k].(float64)
	return v
}

// evaluate turns one agent record into findings and updates the derived
// state (ports, canaries, known logins). Caller holds s.mu.
func (s *Server) evaluate(a *AgentRec, r *Record) []finding {
	d := r.Event.Data
	if d == nil {
		d = map[string]any{}
	}
	host := a.Name
	var out []finding
	add := func(rule, key string, params map[string]string) {
		if params == nil {
			params = map[string]string{}
		}
		params["host"] = host
		if strings.HasPrefix(rule, "agent.") && time.Now().Before(a.MaintenanceUntil) {
			return // the event itself stays in the log
		}
		out = append(out, finding{Rule: rule, Key: rule + "|" + a.ID + "|" + key, Params: params})
	}

	switch r.Event.Type {
	case "ssh.login":
		user, ip := str(d, "user"), str(d, "ip")
		p := map[string]string{"user": user, "ip": ip, "fingerprint": str(d, "fingerprint"), "comment": str(d, "key_comment")}
		if str(d, "method") == "password" || str(d, "method") == "keyboard-interactive/pam" {
			add("ssh.password_login", user+"|"+ip, p)
		}
		if str(d, "fingerprint") != "" && str(d, "key_file") == "" {
			add("ssh.unknown_key", str(d, "fingerprint"), p)
		}
		k := user + "|" + ip
		if _, known := s.state.KnownLogins[k]; !known {
			add("ssh.new_source", k, p)
		}
		s.state.KnownLogins[k] = r.Event.TS
	case "ssh.failed":
		if num(d, "count") >= 30 {
			add("ssh.bruteforce", str(d, "ip"), map[string]string{"ip": str(d, "ip"), "count": str(d, "count")})
		}
	case "ssh.key_added", "ssh.key_removed":
		add(r.Event.Type, str(d, "file")+"|"+str(d, "fingerprint"), map[string]string{"file": str(d, "file"), "comment": str(d, "comment"), "fingerprint": str(d, "fingerprint")})
	case "user.added":
		rule := "user.added"
		if num(d, "uid") == 0 {
			rule = "user.root"
		}
		add(rule, str(d, "user"), map[string]string{"user": str(d, "user"), "uid": str(d, "uid")})
	case "user.uid_changed":
		if num(d, "uid") == 0 {
			add("user.root", str(d, "user"), map[string]string{"user": str(d, "user"), "uid": "0"})
		}
	case "user.removed":
		add("user.removed", str(d, "user"), map[string]string{"user": str(d, "user")})
	case "file.added", "file.changed", "file.removed":
		cat := str(d, "category")
		if cat == "ssh_keys" {
			break // reported key by key
		}
		rule := "file." + cat
		if _, ok := rules[rule]; !ok {
			rule = "file.other"
		}
		add(rule, str(d, "path"), map[string]string{"path": str(d, "path"), "change": strings.TrimPrefix(r.Event.Type, "file.")})
	case "port.snapshot":
		ports, _ := d["ports"].([]any)
		a.Ports = a.Ports[:0]
		for _, p := range ports {
			if m, ok := p.(map[string]any); ok {
				a.Ports = append(a.Ports, m)
			}
		}
		if !a.BaselineSet {
			a.Baseline = map[string]bool{}
			for _, p := range a.Ports {
				a.Baseline[str(p, "key")] = true
			}
			a.BaselineSet = true
		}
	case "port.opened":
		if !a.BaselineSet || portExpected(a, d) {
			break
		}
		// sshd opens 127.0.0.1:60xx for every X11-forwarded session.
		if port := num(d, "port"); str(d, "scope") == "loopback" && strings.HasPrefix(str(d, "process"), "sshd") && port >= 6010 && port < 6100 {
			break
		}
		p := map[string]string{"proto": str(d, "proto"), "port": str(d, "port"), "addr": str(d, "addr"), "process": str(d, "process"), "key": str(d, "key")}
		switch {
		case str(d, "via") == "docker" && str(d, "scope") != "loopback":
			add("port.docker", str(d, "key"), p)
		case str(d, "scope") == "loopback":
			add("port.local", str(d, "key"), p)
		default:
			add("port.public", str(d, "key"), p)
		}
	case "canary.opened":
		exe := str(d, "exe")
		if exe == "" {
			exe = str(d, "comm")
		}
		if exe == "" {
			exe = "pid " + str(d, "pid")
		}
		p := map[string]string{"path": str(d, "path"), "exe": exe, "uid": str(d, "uid"), "pid": str(d, "pid")}
		if anc, ok := d["ancestry"].([]any); ok && len(anc) > 0 {
			names := make([]string, 0, len(anc))
			for _, x := range anc {
				names = append(names, fmt.Sprint(x))
			}
			p["parents"] = strings.Join(names, " < ")
		}
		if c := s.state.Canaries[str(d, "canary_id")]; c != nil {
			c.Triggers++
			c.LastTrigg = r.Event.TS
		}
		add("canary.opened", str(d, "canary_id")+"|"+str(d, "pid"), p)
	case "canary.tampered":
		if c := s.state.Canaries[str(d, "canary_id")]; c != nil {
			c.Status = "tampered"
		}
		add("canary.tampered", str(d, "canary_id"), map[string]string{"path": str(d, "path"), "problem": str(d, "problem")})
	case "canary.placed":
		if c := s.state.Canaries[str(d, "canary_id")]; c != nil {
			c.Status, c.Error = "active", ""
		}
	case "canary.error":
		if c := s.state.Canaries[str(d, "canary_id")]; c != nil {
			c.Status, c.Error = "error", str(d, "error")
		}
	case "canary.remove_failed":
		add("canary.remove_failed", str(d, "canary_id"), map[string]string{"path": str(d, "path"), "error": str(d, "error")})
	case "canary.overflow":
		add("canary.overflow", "", nil)
	case "agent.started":
		if a.StartedOnce {
			gap := "?"
			if !a.prevSeen.IsZero() {
				gap = r.Event.TS.Sub(a.prevSeen).Round(time.Second).String()
			}
			add("agent.restarted", r.Event.TS.Format(time.RFC3339), map[string]string{"gap": gap})
		}
		a.StartedOnce = true
		a.Stopped = false
		if v := str(d, "version"); v != "" {
			a.Version = v
		}
		a.CanaryRoots = a.CanaryRoots[:0]
		if roots, ok := d["canary_roots"].([]any); ok {
			for _, root := range roots {
				if v, ok := root.(string); ok {
					a.CanaryRoots = append(a.CanaryRoots, v)
				}
			}
		}
	case "agent.stopping":
		a.Stopped = true
		add("agent.stopped", "", nil)
	case "agent.config_rejected":
		add("agent.config_rejected", str(d, "reason"), map[string]string{"reason": str(d, "reason")})
	case "log.spoofed":
		add("log.spoofed", str(d, "comm")+"|"+str(d, "uid"), map[string]string{"identifier": str(d, "identifier"), "comm": str(d, "comm"), "uid": str(d, "uid")})
	case "agent.dropped":
		add("agent.dropped", "", map[string]string{"count": str(d, "count")})
	}
	return out
}

// procKey allows every port a named process opens with this protocol and
// scope. Game servers and similar tools pick random ports on each start.
func procKey(p map[string]any) string {
	name, _, _ := strings.Cut(str(p, "process"), "/")
	if name == "" {
		return ""
	}
	return "proc:" + name + "/" + str(p, "proto") + "/" + str(p, "scope")
}

func portExpected(a *AgentRec, p map[string]any) bool {
	if a.Baseline[str(p, "key")] {
		return true
	}
	k := procKey(p)
	return k != "" && a.Baseline[k]
}

// raise records findings as alerts. A finding whose key matches an open
// alert from the last 24 hours only bumps that alert's counter.
// Caller holds s.mu. Returns the alerts that are new.
func (s *Server) raise(fs []finding, agentID string, seq uint64) []*Alert {
	var fresh []*Alert
	now := time.Now().UTC()
	for _, f := range fs {
		def, _ := lookupRule(f.Rule)
		if s.suppressed(f, agentID, now) != nil {
			continue
		}
		var hit *Alert
		for i := len(s.state.Alerts) - 1; i >= 0; i-- {
			al := s.state.Alerts[i]
			if al.Key == f.Key && al.Status == "open" && now.Sub(al.Updated) < 24*time.Hour {
				hit = al
				break
			}
		}
		if hit != nil {
			if severityRank[def.Severity] > severityRank[hit.Severity] {
				hit.Severity = def.Severity
			}
			hit.Count++
			hit.Updated = now
			if len(hit.Seqs) < 20 && seq > 0 {
				hit.Seqs = append(hit.Seqs, seq)
			}
			continue
		}
		al := &Alert{
			ID: newID(8), Key: f.Key, Rule: f.Rule, Severity: def.Severity, Technique: def.Technique,
			Detail: encodeParams(f.Params),
			Agent:  agentID, Created: now, Updated: now, Count: 1, Status: "open",
		}
		al.Title = renderTitle(f.Rule, decodeParams(al.Detail), "en")
		if seq > 0 {
			al.Seqs = []uint64{seq}
		}
		s.state.Alerts = append(s.state.Alerts, al)
		fresh = append(fresh, al)
	}
	if over := len(s.state.Alerts) - maxAlerts; over > 0 {
		s.state.Alerts = append([]*Alert{}, s.state.Alerts[over:]...)
	}
	return fresh
}

// Params are kept as "k=v" lines so titles can be rendered per language.
// Params carry agent-controlled strings into notification titles and mail
// headers, so control characters (CR included) are dropped here.
func cleanParam(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, v)
	if len(v) > 300 {
		v = v[:300]
	}
	return v
}

func encodeParams(p map[string]string) string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(cleanParam(k) + "=" + cleanParam(p[k]) + "\n")
	}
	return b.String()
}

func decodeParams(s string) map[string]string {
	p := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			p[k] = v
		}
	}
	return p
}

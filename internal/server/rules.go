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
	"process.reverse_shell":    {"critical", "T1059.004", "Reverse shell: {exe} started by {parent} (uid {uid})", "Reverse-Shell: {exe} gestartet von {parent} (uid {uid})"},
	"process.miner":            {"critical", "T1496", "Crypto miner started: {exe} (uid {uid})", "Krypto-Miner gestartet: {exe} (uid {uid})"},
	"process.service_shell":    {"high", "T1505.003", "{parent} started {exe} (uid {uid})", "{parent} hat {exe} gestartet (uid {uid})"},
	"process.download_exec":    {"high", "T1105", "Download and run: {cmdline}", "Herunterladen und ausführen: {cmdline}"},
	"process.deleted_exe":      {"high", "T1070.004", "Program running from a deleted file: {exe}", "Programm läuft aus gelöschter Datei: {exe}"},
	"process.memfd_exec":       {"high", "T1620", "Program running from memory only: {exe} (uid {uid}, started by {parent})", "Programm läuft nur aus dem Speicher: {exe} (uid {uid}, gestartet von {parent})"},
	"process.preload":          {"high", "T1574.006", "{exe} started with LD_PRELOAD={lib} (uid {uid})", "{exe} mit LD_PRELOAD={lib} gestartet (uid {uid})"},
	"process.tmp_exec":         {"medium", "T1204.002", "Program started from a temporary directory: {exe} (uid {uid})", "Programm aus temporärem Verzeichnis gestartet: {exe} (uid {uid})"},
	"process.decode_exec":      {"medium", "T1140", "Decoded command run in a shell: {cmdline}", "Dekodierter Befehl in einer Shell ausgeführt: {cmdline}"},
	"updates.security_pending": {"medium", "", "{count} security updates pending for {days} days: {packages}", "{count} Sicherheitsupdates seit {days} Tagen offen: {packages}"},
	"updates.reboot_pending":   {"low", "", "Reboot pending for {days} days ({packages})", "Neustart seit {days} Tagen ausstehend ({packages})"},
	"updates.disabled":         {"low", "", "Automatic security updates are off", "Automatische Sicherheitsupdates sind aus"},
	"updates.lists_stale":      {"low", "", "Package lists not refreshed for {days} days", "Paketlisten seit {days} Tagen nicht aktualisiert"},
	"net.c2":                   {"critical", "T1071", "{process} connected to {ip}:{port}, listed as command and control ({list})", "{process} hat sich mit {ip}:{port} verbunden, gelistet als Command-and-Control ({list})"},
	"net.blocklisted":          {"high", "T1071", "{process} connected to {ip}:{port} on a block list ({list})", "{process} hat sich mit {ip}:{port} auf einer Sperrliste verbunden ({list})"},
	"net.tor":                  {"medium", "T1090.003", "{process} connected to Tor exit {ip}:{port}", "{process} hat sich mit Tor-Ausgang {ip}:{port} verbunden"},
	"net.miner_pool":           {"high", "T1496", "{process} connected to {ip}:{port}, a common mining pool port", "{process} hat sich mit {ip}:{port} verbunden, ein üblicher Mining-Pool-Port"},
	"net.service_outbound":     {"high", "T1572", "{process} opened a connection to the internet: {ip}:{port}", "{process} hat eine Verbindung ins Internet geöffnet: {ip}:{port}"},
	"web.exploit_success":      {"high", "T1190", "Attack on {log} from {ip} answered with 2xx ({kinds})", "Angriff auf {log} von {ip} mit 2xx beantwortet ({kinds})"},
	"web.shell_access":         {"high", "T1505.003", "Web shell path answered with 2xx for {ip}: {sample}", "Webshell-Pfad für {ip} mit 2xx beantwortet: {sample}"},
	"web.login_bruteforce":     {"medium", "T1110", "{logins} login attempts in one minute from {ip}", "{logins} Anmeldeversuche in einer Minute von {ip}"},
	"process.rate_limited":     {"low", "", "{dropped} suspicious program starts not reported (limit reached)", "{dropped} auffällige Programmstarts nicht gemeldet (Grenze erreicht)"},
	"ssh.password_login":       {"high", "T1078", "Password login as {user} from {ip}", "Passwort-Anmeldung als {user} von {ip}"},
	"ssh.new_source":           {"medium", "T1078", "{user} logged in from new address {ip}", "{user} hat sich von neuer Adresse {ip} angemeldet"},
	"ssh.unknown_key":          {"high", "T1098.004", "Login as {user} with a key not in authorized_keys ({fingerprint})", "Anmeldung als {user} mit Schlüssel außerhalb von authorized_keys ({fingerprint})"},
	"ssh.bruteforce":           {"low", "T1110", "{count} failed SSH logins from {ip}", "{count} fehlgeschlagene SSH-Anmeldungen von {ip}"},
	"ssh.key_added":            {"high", "T1098.004", "SSH key added to {file}: {comment}", "SSH-Schlüssel hinzugefügt in {file}: {comment}"},
	"ssh.key_removed":          {"low", "", "SSH key removed from {file}: {comment}", "SSH-Schlüssel entfernt aus {file}: {comment}"},

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

	"agent.silent":               {"high", "T1562.001", "Agent {host} silent", "Agent {host} meldet sich nicht"},
	"agent.stopped":              {"high", "T1562.001", "Agent {host} was stopped", "Agent {host} wurde beendet"},
	"agent.restarted":            {"high", "T1562.001", "Agent {host} restarted after {gap} without monitoring", "Agent {host} neu gestartet nach {gap} ohne Überwachung"},
	"agent.config_rejected":      {"high", "T1557", "Agent {host} rejected a configuration ({reason})", "Agent {host} hat eine Konfiguration abgelehnt ({reason})"},
	"log.spoofed":                {"high", "T1070", "Fake {identifier} log entry written by {comm} (uid {uid})", "Gefälschter {identifier}-Logeintrag von {comm} (uid {uid})"},
	"agent.dropped":              {"low", "", "Agent {host} dropped {count} events", "Agent {host} hat {count} Ereignisse verworfen"},
	"agent.forged":               {"high", "T1557", "Request with invalid signature for agent {agent} from {ip}", "Anfrage mit ungültiger Signatur für Agent {agent} von {ip}"},
	"file.suid":                  {"high", "T1548.001", "{what} on {path} ({why})", "{what} auf {path} ({why})"},
	"file.suid_tmp":              {"critical", "T1548.001", "Root {what} program in a temp directory: {path}", "Root-Programm mit {what} in einem Temp-Verzeichnis: {path}"},
	"file.suid_packaged":         {"low", "T1548.001", "{what} on {path} from package {package}", "{what} auf {path} aus Paket {package}"},
	"integrity.binary_replaced":  {"critical", "T1554", "{path} from {package} was modified: {reason}", "{path} aus {package} wurde verändert: {reason}"},
	"integrity.modified":         {"high", "T1554", "{path} from {package} was modified: {reason}", "{path} aus {package} wurde verändert: {reason}"},
	"integrity.unowned":          {"medium", "T1554", "New program {path} that no package installed", "Neues Programm {path}, das kein Paket installiert hat"},
	"integrity.many":             {"high", "T1554", "{count} packaged files differ from their checksums", "{count} Paketdateien weichen von ihren Prüfsummen ab"},
	"kernel.bpf":                 {"high", "T1014", "eBPF {type} program {name} loaded (uid {uid})", "eBPF-{type}-Programm {name} geladen (uid {uid})"},
	"kernel.module":              {"low", "T1547.006", "Kernel module {name} loaded", "Kernelmodul {name} geladen"},
	"kernel.module_unsigned":     {"high", "T1547.006", "Out-of-tree or unsigned kernel module {name} ({taint})", "Fremdes oder unsigniertes Kernelmodul {name} ({taint})"},
	"kernel.module_hidden":       {"critical", "T1014", "Kernel module {name} is hidden from /proc/modules", "Kernelmodul {name} ist vor /proc/modules versteckt"},
	"kernel.tainted":             {"medium", "T1014", "Kernel tainted: {added} (now {tainted})", "Kernel markiert: {added} (jetzt {tainted})"},
	"posture.ssh_root_login":     {"high", "T1110", "Root can log in over SSH with a password (PermitRootLogin {value})", "Root kann sich per SSH mit Passwort anmelden (PermitRootLogin {value})"},
	"posture.ssh_password":       {"medium", "T1110", "SSH accepts passwords ({value})", "SSH akzeptiert Passwörter ({value})"},
	"posture.ssh_empty_password": {"critical", "T1078", "SSH accepts empty passwords", "SSH akzeptiert leere Passwörter"},
	"posture.empty_password":     {"critical", "T1078", "Accounts with a shell and no password: {value}", "Konten mit Shell und ohne Passwort: {value}"},
	"posture.aslr":               {"medium", "", "Address space randomization is weakened (kernel.randomize_va_space = {value})", "Adressraum-Randomisierung ist geschwächt (kernel.randomize_va_space = {value})"},
	"posture.sysctl":             {"low", "", "{key} = {value}, should be {want}", "{key} = {value}, sollte {want} sein"},
	"posture.permissions":        {"high", "", "Unsafe permissions on {key}: {value}", "Unsichere Rechte auf {key}: {value}"},
	"posture.firewall":           {"medium", "", "No firewall filters incoming traffic", "Keine Firewall filtert eingehenden Verkehr"},
	"posture.mac":                {"low", "", "No AppArmor or SELinux confines services ({value})", "Kein AppArmor oder SELinux schränkt Dienste ein ({value})"},
	"tls.expired":                {"high", "", "Certificate {subject} expired {ago} days ago ({path})", "Zertifikat {subject} ist seit {ago} Tagen abgelaufen ({path})"},
	"tls.expiring":               {"medium", "", "Certificate {subject} expires in {days} days ({path})", "Zertifikat {subject} läuft in {days} Tagen ab ({path})"},
	"backup.missing":             {"high", "T1490", "Backup {name}: no file matches {path}", "Backup {name}: keine Datei passt zu {path}"},
	"backup.stale":               {"high", "T1490", "Backup {name} is {age} hours old (limit {max})", "Backup {name} ist {age} Stunden alt (Grenze {max})"},
	"backup.small":               {"medium", "T1490", "Backup {name} is only {size} bytes ({file})", "Backup {name} hat nur {size} Bytes ({file})"},
	"secret.exposed":             {"high", "T1552.001", "{kind} readable by every user: {path} line {line}", "{kind} für alle Benutzer lesbar: {path} Zeile {line}"},
	"vuln.exploited":             {"critical", "T1190", "{package} {installed}: {count} vulnerabilities exploited in the wild ({cves}), fixed in {fixed}", "{package} {installed}: {count} aktiv ausgenutzte Schwachstellen ({cves}), behoben in {fixed}"},
	"vuln.severe":                {"high", "", "{package} {installed}: {count} high or critical vulnerabilities ({cves}), fixed in {fixed}", "{package} {installed}: {count} hohe oder kritische Schwachstellen ({cves}), behoben in {fixed}"},
	"process.rare":               {"low", "T1204.002", "First run of {exe} on this host, no package installed it (started by {parent})", "{exe} läuft zum ersten Mal auf diesem Host, kein Paket hat es installiert (gestartet von {parent})"},
	"process.rare_child":         {"medium", "T1059", "{parent} started {exe} for the first time (uid {uid})", "{parent} hat zum ersten Mal {exe} gestartet (uid {uid})"},
	"ssh.rare_time":              {"low", "T1078", "{user} logged in at {hour}:00 UTC, an hour without logins in {logins} before ({ip})", "{user} hat sich um {hour}:00 UTC angemeldet, eine Uhrzeit ohne Anmeldungen in {logins} bisherigen ({ip})"},
	"net.volume_spike":           {"medium", "T1048", "{sent} sent in one hour, usually at most {usual}", "{sent} in einer Stunde gesendet, sonst höchstens {usual}"},
	"net.retro_hit":              {"high", "T1071", "{process} talked to {ip} on {when}, now listed by {list}", "{process} hat am {when} mit {ip} gesprochen, jetzt gelistet von {list}"},
	"chain.broken":               {"critical", "T1565.001", "Event chain broken: {error}", "Ereigniskette gebrochen: {error}"},
	"selftest.failed":            {"high", "T1562.001", "Self test on {host} failed: {missing}", "Selbsttest auf {host} fehlgeschlagen: {missing}"},
	"notify.failed":              {"high", "", "Notifier {notifier} ({type}) failed: {error}", "Benachrichtigung {notifier} ({type}) fehlgeschlagen: {error}"},
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
		if hour, total, rare := s.loginHour(user, recordTime(*r)); rare {
			p2 := map[string]string{"user": user, "ip": ip, "hour": fmt.Sprintf("%02d", hour), "logins": fmt.Sprint(total)}
			add("ssh.rare_time", user+"|"+recordTime(*r).Format("2006-01-02T15"), p2)
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
		a.ResponseTypes = strSlice(d["response"])
		a.SelfTest, _ = d["selftest"].(bool)
		a.Forensics, _ = d["forensics"].(bool)
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
	case "process.exec":
		p := map[string]string{"exe": str(d, "exe"), "cmdline": str(d, "cmdline"), "uid": str(d, "uid"),
			"parent": str(d, "parent_comm"), "parent_exe": str(d, "parent_exe"), "cwd": str(d, "cwd"), "pid": str(d, "pid"),
			"lib": str(d, "ld_preload")}
		key := str(d, "exe") + "|" + str(d, "parent_exe")
		seen := map[string]bool{}
		for _, sig := range strSlice(d["signals"]) {
			rule := map[string]string{"shell_socket": "process.reverse_shell", "cmd_reverse_shell": "process.reverse_shell",
				"cmd_miner": "process.miner", "service_shell": "process.service_shell", "cmd_download_exec": "process.download_exec",
				"deleted_exe": "process.deleted_exe", "tmp_exe": "process.tmp_exec", "cmd_decode_exec": "process.decode_exec",
				"memfd_exe": "process.memfd_exec", "ld_preload": "process.preload"}[sig]
			if rule != "" && !seen[rule] {
				seen[rule] = true
				k := key
				if rule == "process.preload" {
					k = str(d, "exe") + "|" + p["lib"]
				}
				add(rule, k, p)
			}
		}
	case "system.updates":
		cp := map[string]any{}
		for k, v := range d {
			cp[k] = v
		}
		a.Updates = cp
		pk := strSlice(d["security_packages"])
		if len(pk) > 5 {
			pk = append(pk[:5], "…")
		}
		if num(d, "security") > 0 && num(d, "security_oldest_days") >= 7 {
			add("updates.security_pending", "", map[string]string{"count": str(d, "security"), "days": str(d, "security_oldest_days"), "packages": strings.Join(pk, ", ")})
		}
		if b, _ := d["reboot_required"].(bool); b && num(d, "reboot_days") >= 7 {
			rp := strSlice(d["reboot_packages"])
			if len(rp) > 3 {
				rp = append(rp[:3], "…")
			}
			add("updates.reboot_pending", "", map[string]string{"days": str(d, "reboot_days"), "packages": strings.Join(rp, ", ")})
		}
		if b, ok := d["unattended_upgrades"].(bool); ok && !b {
			add("updates.disabled", "", nil)
		}
		if num(d, "lists_age_days") >= 7 {
			add("updates.lists_stale", "", map[string]string{"days": str(d, "lists_age_days")})
		}
	case "net.connection":
		ip, port, proc := str(d, "remote_ip"), str(d, "remote_port"), str(d, "process")
		p := map[string]string{"ip": ip, "port": port, "process": proc, "exe": str(d, "exe"), "uid": str(d, "uid")}
		key := ip + "|" + proc
		if list, ok := s.intel.lookup(ip); ok {
			p["list"] = list
			switch list {
			case "feodo", "threatfox":
				add("net.c2", key, p)
			case "tor-exit":
				add("net.tor", key, p)
			default:
				add("net.blocklisted", key, p)
			}
		}
		if netPublic(ip) {
			if minerPorts[int(num(d, "remote_port"))] {
				add("net.miner_pool", key, p)
			}
			if serviceProcesses[proc] {
				add("net.service_outbound", key, p)
			}
		}
	case "web.activity":
		samples := strSlice(d["samples"])
		p := map[string]string{"ip": str(d, "ip"), "log": str(d, "log"), "kinds": strings.Join(strSlice(d["exploit_kinds"]), ", "),
			"logins": str(d, "logins"), "requests": str(d, "requests"), "user_agent": str(d, "user_agent"), "sample": strings.Join(samples, "  ")}
		if num(d, "exploits_ok") > 0 {
			add("web.exploit_success", str(d, "ip"), p)
		}
		if num(d, "shells") > 0 {
			if len(samples) > 0 {
				p["sample"] = samples[len(samples)-1]
			}
			add("web.shell_access", str(d, "ip"), p)
		}
		if num(d, "logins") >= 20 {
			add("web.login_bruteforce", str(d, "ip"), p)
		}
	case "file.suid":
		p := map[string]string{"path": str(d, "path"), "bits": str(d, "bits"), "caps": str(d, "caps"), "mode": str(d, "mode"),
			"package": str(d, "package"), "uid": str(d, "uid")}
		what := strings.Trim(p["bits"]+" "+p["caps"], " ")
		p["what"] = what
		danger, _ := d["dangerous_caps"].(bool)
		if p["bits"] == "" && !danger {
			break // only harmless capabilities such as cap_net_bind_service
		}
		packaged, _ := d["pkgdb"].(bool)
		packaged = packaged && p["package"] != ""
		after, _ := d["changed_after_install"].(bool)
		rootOwned := p["uid"] == "0" || danger
		switch {
		case str(d, "where") == "tmp" && rootOwned:
			add("file.suid_tmp", p["path"], p)
		case packaged && !after:
			add("file.suid_packaged", p["path"], p)
		default:
			if after {
				p["why"] = "set after the package " + p["package"] + " was installed"
			} else if p["package"] == "" {
				p["why"] = "no package owns it"
			}
			add("file.suid", p["path"], p)
		}
	case "integrity.mismatch":
		p := map[string]string{"path": str(d, "path"), "package": str(d, "package"), "version": str(d, "version"),
			"reason": str(d, "reason"), "sha256": str(d, "sha256")}
		if crit, _ := d["critical"].(bool); crit {
			add("integrity.binary_replaced", p["path"], p)
		} else {
			add("integrity.modified", p["path"], p)
		}
	case "integrity.unowned":
		add("integrity.unowned", str(d, "path"), map[string]string{"path": str(d, "path"), "sha256": str(d, "sha256")})
	case "integrity.many":
		add("integrity.many", "", map[string]string{"count": str(d, "count")})
	case "kernel.bpf_loaded":
		p := map[string]string{"type": str(d, "type"), "name": str(d, "name"), "tag": str(d, "tag"), "uid": str(d, "uid")}
		if p["name"] == "" {
			p["name"] = "(unnamed)"
		}
		add("kernel.bpf", p["type"]+"|"+p["name"]+"|"+p["tag"], p)
	case "kernel.baseline":
		for _, m := range strSlice(d["out_of_tree"]) {
			name, taint, _ := strings.Cut(m, " (")
			add("kernel.module_unsigned", name, map[string]string{"name": name, "taint": strings.TrimSuffix(taint, ")")})
		}
	case "kernel.module_loaded":
		p := map[string]string{"name": str(d, "name"), "taint": str(d, "taint")}
		if strings.ContainsAny(p["taint"], "OEP") {
			add("kernel.module_unsigned", p["name"], p)
		} else {
			add("kernel.module", p["name"], p)
		}
	case "kernel.module_hidden":
		add("kernel.module_hidden", str(d, "name"), map[string]string{"name": str(d, "name")})
	case "kernel.tainted":
		add("kernel.tainted", str(d, "added"), map[string]string{"added": str(d, "added"), "tainted": str(d, "tainted")})
	case "posture.report":
		cp := map[string]any{}
		for k, v := range d {
			cp[k] = v
		}
		a.Posture = cp
		out = append(out, s.conditionFindings(a, "posture", postureConditions(d))...)
	case "secret.exposed":
		p := map[string]string{"path": str(d, "path"), "kind": secretKind(str(d, "kind")), "line": str(d, "line"),
			"fingerprint": str(d, "fingerprint"), "uid": str(d, "uid"), "mode": str(d, "mode")}
		// One alert per file; further secrets in it count on that alert.
		add("secret.exposed", p["path"], p)
	case "process.rare":
		add("process.rare", str(d, "exe"), map[string]string{"exe": str(d, "exe"), "parent": str(d, "parent_comm"), "uid": str(d, "uid"),
			"cmdline": str(d, "cmdline"), "pid": str(d, "pid")})
	case "process.rare_child":
		add("process.rare_child", str(d, "parent_comm")+"|"+str(d, "exe"), map[string]string{"exe": str(d, "exe"), "parent": str(d, "parent_comm"),
			"uid": str(d, "uid"), "cmdline": str(d, "cmdline"), "pid": str(d, "pid")})
	case "net.volume":
		if f := volumeFinding(a, d, recordTime(*r)); f != nil {
			add("net.volume_spike", recordTime(*r).Format("2006-01-02T15"), f)
		}
	case "forensics.snapshot":
		s.snapshotReceived(a, r)
	case "system.packages":
		out = append(out, s.packagesReceived(a, d)...)
	case "response.result":
		s.actionResult(a.ID, d)
	case "selftest.started", "selftest.step", "selftest.done":
		s.selfTestEvent(a, r.Event.Type, d)
	case "process.rate_limited":
		add("process.rate_limited", "", map[string]string{"dropped": str(d, "dropped")})
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

func strSlice(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

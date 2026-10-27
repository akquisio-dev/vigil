package server

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The attack report: who attacked the hosts over the last days, from
// where, with what, and what needs a person. Markdown to keep, or a page to
// print as PDF.

var attackReportText = map[string]map[string]string{
	"en": {
		"title": "Attack report", "period": "Period", "hosts": "Hosts", "made": "Made", "figures": "Figures",
		"ips": "Attacking addresses", "ssh": "Failed SSH logins", "web": "Flagged web requests", "countries": "Countries",
		"networks": "Networks", "success": "Successful (logged in or attack answered)", "targeted": "Aimed at these hosts",
		"persistent": "Came back on 3 or more days", "noise": "Mass scanning", "campaigns": "Campaigns",
		"attention": "Needs attention", "none": "Nothing.", "ip": "Address", "country": "Country", "network": "Network",
		"class": "Class", "why": "Why", "last": "Last seen", "addresses": "Addresses", "attempts": "Attempts", "share": "Share",
		"type": "Type", "users": "Most tried user names", "user": "User", "exists": "Account exists", "yes": "yes",
		"webkinds": "Web attacks", "kind": "Kind", "paths": "Most requested attack paths", "path": "Path",
		"signature": "Tried", "first": "First seen", "hours": "Time of day (UTC)", "hour": "Hour", "days": "Per day", "day": "Day",
		"hosting": "data centre", "tor": "Tor", "other": "other", "geo": "Origin data", "nogeo": "Origin data is off (`geoip` in server.json).",
		"overflow":      "Addresses beyond the daily limit were counted but not kept",
		"class_success": "successful", "class_targeted": "aimed", "class_persistent": "persistent", "class_noise": "noise",
		"r_login": "logged in after failing", "r_web_ok": "attack request answered with 2xx", "r_own_account": "tried an account that exists here",
		"r_own_name": "tried a name of these hosts", "r_persistent": "came back on several days", "r_listed": "on a threat list",
		"r_tor": "Tor exit", "r_campaign": "part of a campaign", "r_wordlist": "only word list names", "r_root": "tried root",
	},
	"de": {
		"title": "Angriffsbericht", "period": "Zeitraum", "hosts": "Hosts", "made": "Erstellt", "figures": "Kennzahlen",
		"ips": "Angreifende Adressen", "ssh": "Fehlgeschlagene SSH-Anmeldungen", "web": "Auffällige Webanfragen", "countries": "Länder",
		"networks": "Netze", "success": "Erfolgreich (angemeldet oder Angriff beantwortet)", "targeted": "Gezielt auf diese Hosts",
		"persistent": "An 3 oder mehr Tagen wiedergekommen", "noise": "Massenscans", "campaigns": "Kampagnen",
		"attention": "Braucht Aufmerksamkeit", "none": "Nichts.", "ip": "Adresse", "country": "Land", "network": "Netz",
		"class": "Einstufung", "why": "Warum", "last": "Zuletzt", "addresses": "Adressen", "attempts": "Versuche", "share": "Anteil",
		"type": "Art", "users": "Meistversuchte Benutzernamen", "user": "Benutzer", "exists": "Konto existiert", "yes": "ja",
		"webkinds": "Web-Angriffe", "kind": "Art", "paths": "Meistabgefragte Angriffspfade", "path": "Pfad",
		"signature": "Versucht", "first": "Zuerst", "hours": "Tageszeit (UTC)", "hour": "Stunde", "days": "Pro Tag", "day": "Tag",
		"hosting": "Rechenzentrum", "tor": "Tor", "other": "sonstige", "geo": "Herkunftsdaten", "nogeo": "Herkunftsdaten sind aus (`geoip` in server.json).",
		"overflow":      "Adressen über der Tagesgrenze wurden gezählt, aber nicht gespeichert",
		"class_success": "erfolgreich", "class_targeted": "gezielt", "class_persistent": "hartnäckig", "class_noise": "Rauschen",
		"r_login": "nach Fehlversuchen angemeldet", "r_web_ok": "Angriffsanfrage mit 2xx beantwortet", "r_own_account": "hat ein hier existierendes Konto versucht",
		"r_own_name": "hat einen Namen dieser Hosts versucht", "r_persistent": "an mehreren Tagen wiedergekommen", "r_listed": "auf einer Bedrohungsliste",
		"r_tor": "Tor-Ausgang", "r_campaign": "Teil einer Kampagne", "r_wordlist": "nur Namen aus Wortlisten", "r_root": "hat root versucht",
	},
}

func (s *Server) attackMarkdown(v *attackView, lg, by string) string {
	tx := attackReportText["en"]
	if lg == "de" {
		tx = attackReportText["de"]
	}
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	from, to := v.PerDay[0].Day, v.PerDay[len(v.PerDay)-1].Day
	names := s.agentNames()
	var hosts []string
	for _, n := range names {
		hosts = append(hosts, n)
	}
	sort.Strings(hosts)
	p("# %s %s\n\n| | |\n|---|---|\n", tx["title"], to)
	p("| %s | %s, %s (UTC) |\n| %s | %s |\n| %s | %s, %s |\n\n", tx["period"], from, to, tx["hosts"], mdEscape(strings.Join(hosts, ", ")),
		tx["made"], v.Generated.Format("2006-01-02 15:04 UTC"), mdEscape(by))
	t := v.Totals
	p("## %s\n\n| | |\n|---|---|\n", tx["figures"])
	for _, row := range [][2]any{{tx["ips"], t.IPs}, {tx["ssh"], t.SSH}, {tx["web"], t.Web}, {tx["countries"], t.Countries},
		{tx["networks"], t.Networks}, {tx["success"], t.Success}, {tx["targeted"], t.Targeted}, {tx["persistent"], t.Persistent},
		{tx["noise"], t.Noise}, {tx["campaigns"], t.Campaigns}} {
		p("| %s | %v |\n", row[0], row[1])
	}
	if t.Overflow > 0 {
		p("| %s | %d |\n", tx["overflow"], t.Overflow)
	}
	why := func(a addrView) string {
		var out []string
		for _, r := range a.Reasons {
			out = append(out, tx["r_"+r])
		}
		return strings.Join(out, ", ")
	}
	netName := func(a addrView) string {
		if a.ASN == 0 {
			return ""
		}
		return fmt.Sprintf("AS%d %s", a.ASN, a.Org)
	}
	p("\n## %s\n\n", tx["attention"])
	n := 0
	for _, a := range v.Addresses {
		if a.Class != "success" && a.Class != "targeted" {
			continue
		}
		if n == 0 {
			p("| %s | %s | %s | %s | %s | SSH | Web | %s |\n|---|---|---|---|---|---|---|---|\n", tx["ip"], tx["country"], tx["network"], tx["class"], tx["why"], tx["last"])
		}
		n++
		p("| `%s` | %s | %s | %s | %s | %d | %d | %s |\n", a.IP, a.Country, mdEscape(netName(a)), tx["class_"+a.Class], why(a), a.SSH, a.Web,
			a.Last.UTC().Format("2006-01-02 15:04"))
		if n >= 40 {
			break
		}
	}
	if n == 0 {
		p("%s\n", tx["none"])
	}
	total := t.SSH + t.Web
	if total == 0 {
		total = 1
	}
	p("\n## %s\n\n| %s | %s | %s | %s |\n|---|---|---|---|\n", tx["countries"], tx["country"], tx["addresses"], tx["attempts"], tx["share"])
	for i, c := range v.Countries {
		if i >= 15 {
			break
		}
		p("| %s | %d | %d | %.1f %% |\n", c.Key, c.IPs, c.Count, float64(c.Count)*100/float64(total))
	}
	p("\n## %s\n\n| AS | %s | %s | %s | %s | %s |\n|---|---|---|---|---|---|\n", tx["networks"], tx["network"], tx["country"], tx["type"], tx["addresses"], tx["attempts"])
	for i, nw := range v.Networks {
		if i >= 15 {
			break
		}
		kind := nw.Net
		if kind == "" {
			kind = "other"
		}
		p("| %d | %s | %s | %s | %d | %d |\n", nw.ASN, mdEscape(nw.Org), nw.Country, tx[kind], nw.IPs, nw.Count)
	}
	p("\n## %s\n\n| %s | %s | %s |\n|---|---|---|\n", tx["users"], tx["user"], tx["addresses"], tx["exists"])
	for i, u := range v.Users {
		if i >= 20 {
			break
		}
		ex := ""
		if u.Existing {
			ex = tx["yes"]
		}
		p("| `%s` | %d | %s |\n", mdEscape(u.User), u.IPs, ex)
	}
	if len(v.WebKinds) > 0 || len(v.Paths) > 0 {
		p("\n## %s\n\n", tx["webkinds"])
		if len(v.WebKinds) > 0 {
			p("| %s | %s |\n|---|---|\n", tx["kind"], tx["addresses"])
			for _, k := range v.WebKinds {
				p("| %s | %d |\n", mdEscape(k.Key), k.IPs)
			}
			p("\n")
		}
		p("| %s | %s |\n|---|---|\n", tx["path"], tx["addresses"])
		for _, k := range v.Paths {
			p("| `%s` | %d |\n", mdEscape(k.Key), k.IPs)
		}
	}
	if len(v.Campaigns) > 0 {
		p("\n## %s\n\n| # | %s | %s | %s | %s | %s | %s | %s |\n|---|---|---|---|---|---|---|---|\n", tx["campaigns"], tx["addresses"], tx["type"],
			tx["signature"], tx["countries"], tx["networks"], tx["first"], tx["last"])
		for i, c := range v.Campaigns {
			if i >= 10 {
				break
			}
			var sig, cc []string
			for _, x := range c.Signature {
				sig = append(sig, x[2:])
			}
			for _, x := range c.Countries {
				cc = append(cc, x.Key+" "+strconv.Itoa(x.IPs))
			}
			p("| %d | %d | %s | %s | %s | %d | %s | %s |\n", i+1, c.Size, c.Kind, mdEscape(strings.Join(sig, ", ")), strings.Join(cc, ", "), c.Networks,
				c.First.UTC().Format("01-02 15:04"), c.Last.UTC().Format("01-02 15:04"))
		}
	}
	max := 1
	for _, h := range v.Hours {
		if h > max {
			max = h
		}
	}
	p("\n## %s\n\n| %s | %s | |\n|---|---|---|\n", tx["hours"], tx["hour"], tx["attempts"])
	for h, c := range v.Hours {
		p("| %02d | %d | `%s` |\n", h, c, strings.Repeat("#", c*30/max))
	}
	p("\n## %s\n\n| %s | %s | SSH | Web |\n|---|---|---|---|\n", tx["days"], tx["day"], tx["addresses"])
	for _, d := range v.PerDay {
		p("| %s | %d | %d | %d |\n", d.Day, d.IPs, d.SSH, d.Web)
	}
	if s.cfg.GeoIP {
		p("\n%s: %s (%s)\n", tx["geo"], GeoAttribution, GeoAttributionURL)
	} else {
		p("\n%s\n", tx["nogeo"])
	}
	return b.String()
}

// GET /api/ui/attacks/report?days=7&format=md|html&lang=de
func (s *Server) handleAttackReport(w http.ResponseWriter, r *http.Request, sess *session) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 7
	}
	v := s.attackStats(days)
	md := s.attackMarkdown(v, lang(r), sess.User)
	s.audit(sess.User, "admin.attack_report", map[string]any{"days": v.Days, "format": r.URL.Query().Get("format")})
	w.Header().Set("Cache-Control", "no-store")
	name := "attacks-" + time.Now().UTC().Format("2006-01-02")
	if r.URL.Query().Get("format") == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		footer := ""
		if s.cfg.GeoIP {
			// the licence asks for a link on pages that show its results
			footer = `<p style="font-size:11px;color:#6b6b67"><a href="` + GeoAttributionURL + `">` + GeoAttribution + `</a></p>`
		}
		w.Write([]byte(mdPage(name, md, footer)))
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.md"`)
	w.Write([]byte(md))
}

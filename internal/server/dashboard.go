package server

import (
	"sort"
	"strings"
	"time"
)

// tactics maps the techniques the rules use to their primary ATT&CK tactic.
// Techniques that belong to several tactics are listed under the one that
// fits how vigil detects them.
var tactics = map[string]string{
	"T1078":     "initial-access",
	"T1078.003": "initial-access",
	"T1053.003": "persistence",
	"T1098":     "persistence",
	"T1098.004": "persistence",
	"T1136.001": "persistence",
	"T1543.002": "persistence",
	"T1546.004": "persistence",
	"T1574.006": "persistence",
	"T1548.003": "privilege-escalation",
	"T1059.004": "execution",
	"T1204.002": "execution",
	"T1505.003": "persistence",
	"T1140":     "defense-evasion",
	"T1105":     "command-and-control",
	"T1190":     "initial-access",
	"T1195.002": "initial-access",
	"T1611":     "privilege-escalation",
	"T1610":     "execution",
	"T1548":     "privilege-escalation",
	"T1071":     "command-and-control",
	"T1090.003": "command-and-control",
	"T1572":     "command-and-control",
	"T1496":     "impact",
	"T1070":     "defense-evasion",
	"T1070.004": "defense-evasion",
	"T1562.001": "defense-evasion",
	"T1110":     "credential-access",
	"T1552.001": "credential-access",
	"T1556.003": "credential-access",
	"T1557":     "credential-access",
	"T1531":     "impact",
	"T1565.001": "impact",
	"T1547.006": "persistence",
	"T1554":     "persistence",
	"T1548.001": "privilege-escalation",
	"T1014":     "defense-evasion",
	"T1620":     "defense-evasion",
	"T1490":     "impact",
	"T1048":     "exfiltration",
	"T1059":     "execution",
}

// TacticOrder is the kill chain order of the tactics vigil covers.
var TacticOrder = []string{"initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "command-and-control", "exfiltration", "impact"}

type countItem struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
	Extra string `json:"extra,omitempty"`
}

func topN(m map[string]int, extra map[string]map[string]bool, n int) []countItem {
	out := make([]countItem, 0, len(m))
	for k, c := range m {
		it := countItem{Key: k, Count: c}
		if extra != nil {
			var xs []string
			for x := range extra[k] {
				xs = append(xs, x)
			}
			sort.Strings(xs)
			if len(xs) > 4 {
				xs = append(xs[:4], "…")
			}
			it.Extra = strings.Join(xs, ", ")
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type loginView struct {
	TS     time.Time `json:"ts"`
	Host   string    `json:"host"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Method string    `json:"method"`
	Key    string    `json:"key,omitempty"`
}

// dashboard aggregates what the overview shows beyond the raw counters:
// alerts per day by severity, ATT&CK tactics, top rules, attacking addresses,
// recent logins and the time until a person looked at an alert.
// The caller holds s.mu.
func (s *Server) dashboard(now time.Time, events []Record) map[string]any {
	dayStart := now.Truncate(24 * time.Hour).Add(-6 * 24 * time.Hour)
	perDay := make([]map[string]int, 7)
	for i := range perDay {
		perDay[i] = map[string]int{}
	}
	tacticCount := map[string]int{}
	ruleCount := map[string]int{}
	var ackTimes []time.Duration
	for _, al := range s.state.Alerts {
		if al.Acked != nil && now.Sub(*al.Acked) < 30*24*time.Hour {
			ackTimes = append(ackTimes, al.Acked.Sub(al.Created))
		}
		i := int(al.Created.Sub(dayStart) / (24 * time.Hour))
		if al.Created.Before(dayStart) || i > 6 { // i > 6 only when the clock stepped back
			continue
		}
		perDay[i][al.Severity]++
		ruleCount[al.Rule]++
		if t := tactics[al.Technique]; t != "" {
			tacticCount[t]++
		}
	}
	var mtta any
	if len(ackTimes) > 0 {
		sort.Slice(ackTimes, func(i, j int) bool { return ackTimes[i] < ackTimes[j] })
		mtta = int(ackTimes[len(ackTimes)/2].Seconds())
	}

	failedIP := map[string]int{}
	failedUsers := map[string]map[string]bool{}
	failedTotal, sudo := 0, 0
	webIP := map[string]int{}
	webPaths := map[string]map[string]bool{}
	var logins []loginView
	since := now.Add(-24 * time.Hour)
	for _, rec := range events {
		if rec.Time.Before(since) || rec.Source != "agent" {
			continue
		}
		d := rec.Event.Data
		switch rec.Event.Type {
		case "ssh.failed":
			ip, c := str(d, "ip"), int(num(d, "count"))
			failedIP[ip] += c
			failedTotal += c
			if failedUsers[ip] == nil {
				failedUsers[ip] = map[string]bool{}
			}
			if us, ok := d["users"].([]any); ok {
				for _, u := range us {
					if u, ok := u.(string); ok {
						failedUsers[ip][u] = true
					}
				}
			}
		case "ssh.login":
			host := rec.Agent
			if a := s.state.Agents[rec.Agent]; a != nil {
				host = a.Name
			}
			key := str(d, "key_comment")
			if key == "" {
				key = str(d, "fingerprint")
			}
			logins = append(logins, loginView{TS: rec.Event.TS, Host: host, User: str(d, "user"), IP: str(d, "ip"), Method: str(d, "method"), Key: key})
		case "sudo.command":
			sudo++
		case "web.activity":
			ip := str(d, "ip")
			webIP[ip] += int(num(d, "requests"))
			if webPaths[ip] == nil {
				webPaths[ip] = map[string]bool{}
			}
			for _, sm := range strSlice(d["samples"]) {
				if f := strings.Fields(sm); len(f) > 0 {
					path := f[len(f)-1]
					if i := strings.IndexByte(path, '?'); i > 0 {
						path = path[:i]
					}
					webPaths[ip][path] = true
				}
			}
		}
	}
	sort.Slice(logins, func(i, j int) bool { return logins[i].TS.After(logins[j].TS) })
	loginCount := len(logins)
	if len(logins) > 8 {
		logins = logins[:8]
	}
	if logins == nil {
		logins = []loginView{}
	}
	tacticList := make([]countItem, 0, len(TacticOrder))
	for _, t := range TacticOrder {
		tacticList = append(tacticList, countItem{Key: t, Count: tacticCount[t]})
	}
	return map[string]any{
		"day_start": dayStart, "alerts_per_day": perDay,
		"tactics": tacticList, "top_rules": topN(ruleCount, nil, 6),
		"ssh_failed_24h": failedTotal, "ssh_failed_ips": len(failedIP), "top_attackers": attackers(failedIP, failedUsers, webIP, webPaths),
		"web_flagged_24h": sumValues(webIP), "web_ips": len(webIP),
		"logins": logins, "logins_24h": loginCount, "sudo_24h": sudo,
		"mtta_seconds": mtta, "acked_30d": len(ackTimes),
	}
}

func sumValues(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// attackers ranks addresses by failed SSH logins plus flagged web requests,
// with the users or paths they tried.
func attackers(ssh map[string]int, users map[string]map[string]bool, web map[string]int, paths map[string]map[string]bool) []countItem {
	all := map[string]int{}
	for ip, n := range ssh {
		all[ip] += n
	}
	for ip, n := range web {
		all[ip] += n
	}
	top := topN(all, nil, 6)
	for i := range top {
		var parts []string
		if u := users[top[i].Key]; len(u) > 0 {
			parts = append(parts, "SSH: "+joinSet(u, 4))
		}
		if p := paths[top[i].Key]; len(p) > 0 {
			parts = append(parts, "Web: "+joinSet(p, 3))
		}
		top[i].Extra = strings.Join(parts, "  ·  ")
	}
	return top
}

func joinSet(m map[string]bool, n int) string {
	xs := make([]string, 0, len(m))
	for x := range m {
		xs = append(xs, x)
	}
	sort.Strings(xs)
	if len(xs) > n {
		xs = append(xs[:n], "…")
	}
	return strings.Join(xs, ", ")
}

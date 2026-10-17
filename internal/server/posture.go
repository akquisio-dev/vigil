package server

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Conditions (a weak setting, a certificate close to expiry, a stale backup,
// a known vulnerability) are reported again with every report while they
// last. They alert once when they start and are closed by the system when
// they end, so a condition someone resolved by hand stays quiet until it
// clears and comes back.

type condition struct {
	rule, key string
	params    map[string]string
}

// conditionFindings returns findings for conditions in group that were not
// active before, and resolves the alerts of conditions that ended. Caller
// holds s.mu.
func (s *Server) conditionFindings(a *AgentRec, group string, now []condition) []finding {
	if a.Conditions == nil {
		a.Conditions = map[string]map[string]bool{}
	}
	prev := a.Conditions[group]
	cur := map[string]bool{}
	var out []finding
	for _, c := range now {
		full := c.rule + "|" + a.ID + "|" + c.key
		cur[full] = true
		if prev[full] {
			continue
		}
		if c.params == nil {
			c.params = map[string]string{}
		}
		c.params["host"] = a.Name
		out = append(out, finding{Rule: c.rule, Key: full, Params: c.params})
	}
	for k := range prev {
		if !cur[k] {
			s.resolveKey(k, "system")
		}
	}
	a.Conditions[group] = cur
	return out
}

// resolveKey closes open alerts with exactly this key. Caller holds s.mu.
func (s *Server) resolveKey(key, by string) {
	for _, al := range s.state.Alerts {
		if al.Status == "open" && al.Key == key {
			al.Status, al.By, al.Updated = "resolved", by, time.Now().UTC()
		}
	}
}

func postureConditions(d map[string]any) []condition {
	var out []condition
	checks, _ := d["checks"].([]any)
	for _, x := range checks {
		c, ok := x.(map[string]any)
		if !ok {
			continue
		}
		if b, _ := c["ok"].(bool); b {
			continue
		}
		rule := "posture." + str(c, "check")
		if _, ok := rules[rule]; !ok {
			continue
		}
		out = append(out, condition{rule: rule, key: str(c, "key"),
			params: map[string]string{"key": str(c, "key"), "value": str(c, "value"), "want": str(c, "want")}})
	}
	certs, _ := d["certs"].([]any)
	for _, x := range certs {
		c, ok := x.(map[string]any)
		if !ok || str(c, "error") != "" {
			continue
		}
		days := int(num(c, "days"))
		p := map[string]string{"path": str(c, "path"), "subject": str(c, "subject"), "issuer": str(c, "issuer"),
			"days": fmt.Sprint(days), "ago": fmt.Sprint(-days), "not_after": str(c, "not_after")}
		switch {
		case days < 0:
			out = append(out, condition{"tls.expired", str(c, "path"), p})
		case days < 14:
			out = append(out, condition{"tls.expiring", str(c, "path"), p})
		}
	}
	backups, _ := d["backups"].([]any)
	for _, x := range backups {
		b, ok := x.(map[string]any)
		if !ok {
			continue
		}
		p := map[string]string{"name": str(b, "name"), "path": str(b, "path"), "file": str(b, "newest"),
			"age": str(b, "age_hours"), "max": str(b, "max_age_hours"), "size": str(b, "size")}
		switch str(b, "problem") {
		case "missing":
			out = append(out, condition{"backup.missing", str(b, "name"), p})
		case "old":
			out = append(out, condition{"backup.stale", str(b, "name"), p})
		case "small":
			out = append(out, condition{"backup.small", str(b, "name"), p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rule+out[i].key < out[j].rule+out[j].key })
	return out
}

func secretKind(k string) string {
	return strings.ReplaceAll(k, "_", " ")
}

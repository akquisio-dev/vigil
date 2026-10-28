package server

import (
	"net/http"
	"sort"
	"strconv"
)

// The attackers map filters and sums on the page: it gets every address of
// the window in short rows, not the first 300 the attackers view lists.

const attackMapRows = 20000

// mapCols names the fields of each row of /api/ui/attacks/map.
var mapCols = []string{"ip", "cc", "asn", "net", "class", "ssh", "web", "campaign", "first", "last", "days", "users", "hosts", "kinds", "listed", "lat", "lon"}

// GET /api/ui/attacks/map?days=1|7|30[&agent=]
func (s *Server) handleAttackMap(w http.ResponseWriter, r *http.Request, sess *session) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 7
	}
	agent := r.URL.Query().Get("agent")
	if agent != "" {
		s.mu.Lock()
		_, known := s.state.Agents[agent]
		s.mu.Unlock()
		if !known {
			http.NotFound(w, r)
			return
		}
	}
	writeJSON(w, s.attackMap(s.attackStatsFor(days, agent)))
}

func (s *Server) attackMap(v *attackView) map[string]any {
	list := make([]*addrView, 0, len(v.all))
	for _, av := range v.all {
		list = append(list, av)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].attempts() != list[j].attempts() {
			return list[i].attempts() > list[j].attempts()
		}
		return list[i].IP < list[j].IP
	})
	truncated := len(list) > attackMapRows
	if truncated {
		list = list[:attackMapRows]
	}
	orgs := map[string]string{}
	rows := make([][]any, 0, len(list))
	for _, av := range list {
		users := av.Users
		if len(users) > 5 {
			users = users[:5]
		}
		if av.ASN != 0 {
			orgs[strconv.FormatUint(uint64(av.ASN), 10)] = av.Org
		}
		var lat, lon any
		if y, x, ok := s.place(av.IP); ok {
			lat, lon = y, x
		}
		rows = append(rows, []any{av.IP, av.Country, av.ASN, av.Net, av.Class, av.SSH, av.Web, av.Campaign,
			av.First.Unix(), av.Last.Unix(), av.Days, nonNil(users), nonNil(av.Hosts), nonNil(av.Kinds), av.Listed, lat, lon})
	}
	camps := make([]map[string]any, 0, len(v.Campaigns))
	for _, c := range v.Campaigns {
		camps = append(camps, map[string]any{"id": c.ID, "size": c.Size, "kind": c.Kind, "signature": c.Signature})
	}
	return map[string]any{"days": v.Days, "agent": v.Agent, "ready": v.Ready, "generated": v.Generated, "cols": mapCols, "rows": rows,
		"orgs": orgs, "campaigns": camps, "truncated": truncated, "total": len(v.all), "home": s.cfg.MapHome, "geo": v.Geo}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

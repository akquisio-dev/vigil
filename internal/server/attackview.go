package server

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Views over the attack rollup: totals, countries and networks, tried
// users and paths, campaigns and how aimed each address is.

type dayStat struct {
	Day string `json:"day"`
	SSH int    `json:"ssh"`
	Web int    `json:"web"`
	IPs int    `json:"ips"`
}

type geoCount struct {
	Key   string `json:"key"`
	IPs   int    `json:"ips"`
	Count int    `json:"count"`
}

type netCount struct {
	ASN     uint32 `json:"asn"`
	Org     string `json:"org"`
	Country string `json:"country,omitempty"`
	Net     string `json:"net,omitempty"`
	IPs     int    `json:"ips"`
	Count   int    `json:"count"`
}

// userStat is one tried user name: attempts in total, per day of the window
// and per UTC hour, and how widely it is tried.
type userStat struct {
	User      string  `json:"user"`
	Attempts  int     `json:"attempts"`
	IPs       int     `json:"ips"`
	Countries int     `json:"countries"`
	Existing  bool    `json:"existing,omitempty"`
	Days      []int   `json:"days"`
	Hours     [24]int `json:"hours"`
}

// userMatrix counts attempts per user name (rows) and country (columns).
type userMatrix struct {
	Users     []string `json:"users"`
	Countries []string `json:"countries"`
	Cells     [][]int  `json:"cells"`
}

// flow is one band of the country, user, account diagram.
type flow struct {
	Country  string `json:"country"`
	User     string `json:"user"`
	Existing bool   `json:"existing"`
	Count    int    `json:"count"`
}

type userCount struct {
	User     string `json:"user"`
	IPs      int    `json:"ips"`
	Existing bool   `json:"existing,omitempty"`
}

type addrView struct {
	IP string `json:"ip"`
	GeoInfo
	SSH       int       `json:"ssh"`
	Web       int       `json:"web"`
	Users     []string  `json:"users,omitempty"`
	Existing  []string  `json:"existing,omitempty"`
	Paths     []string  `json:"paths,omitempty"`
	Kinds     []string  `json:"kinds,omitempty"`
	Hosts     []string  `json:"hosts,omitempty"`
	Logins    int       `json:"logins,omitempty"`
	LoginAs   []string  `json:"login_as,omitempty"`
	ExploitOK int       `json:"exploits_ok,omitempty"`
	Shells    int       `json:"shells,omitempty"`
	UA        string    `json:"user_agent,omitempty"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Days      int       `json:"days"`
	Listed    string    `json:"listed,omitempty"`
	// Class is success, targeted, persistent or noise; Reasons say why.
	Class    string   `json:"class"`
	Reasons  []string `json:"reasons,omitempty"`
	Campaign int      `json:"campaign"` // index into campaigns, -1 for none
}

type campaignView struct {
	ID        int        `json:"id"`
	Size      int        `json:"size"`
	Attempts  int        `json:"attempts"`
	Kind      string     `json:"kind"` // ssh | web | both
	Signature []string   `json:"signature"`
	Countries []geoCount `json:"countries"`
	Networks  int        `json:"networks"`
	Hosts     []string   `json:"hosts"`
	First     time.Time  `json:"first"`
	Last      time.Time  `json:"last"`
	Members   []string   `json:"members"`
}

type attackView struct {
	Days int `json:"days"`
	// Agent: only addresses that tried this host; hours and tried users
	// are then not shown (they are kept per day, not per host).
	Agent     string    `json:"agent,omitempty"`
	Ready     bool      `json:"ready"`
	Generated time.Time `json:"generated"`
	Totals    struct {
		IPs        int `json:"ips"`
		SSH        int `json:"ssh"`
		Web        int `json:"web"`
		Countries  int `json:"countries"`
		Networks   int `json:"networks"`
		Success    int `json:"success"`
		Targeted   int `json:"targeted"`
		Persistent int `json:"persistent"`
		Noise      int `json:"noise"`
		Campaigns  int `json:"campaigns"`
		Overflow   int `json:"overflow,omitempty"`
	} `json:"totals"`
	PerDay    []dayStat      `json:"per_day"`
	Hours     [24]int        `json:"hours"`
	Countries []geoCount     `json:"countries"`
	Networks  []netCount     `json:"networks"`
	NetKinds  map[string]int `json:"net_kinds"`
	Users     []userCount    `json:"users"`
	UserStats []userStat     `json:"user_stats"`
	Matrix    userMatrix     `json:"matrix"`
	Flows     []flow         `json:"flows"`
	// Estimated: attempts per user were shared out evenly for some days
	// (agents before v0.26.0 report one total for several users).
	Estimated bool           `json:"estimated,omitempty"`
	Paths     []geoCount     `json:"paths"`
	WebKinds  []geoCount     `json:"web_kinds"`
	Campaigns []campaignView `json:"campaigns"`
	Addresses []addrView     `json:"addresses"`
	Geo       map[string]any `json:"geo"`
	all       map[string]*addrView
}

// commonUsers are names every scanner's word list has; trying them says
// nothing about the target.
var commonUsers = map[string]bool{}

func init() {
	for _, u := range strings.Fields(`root admin administrator user test test1 test2 testuser guest ubuntu debian centos ec2-user pi
		oracle postgres mysql git gitlab ftp ftpuser ftp_user www www-data nginx apache tomcat jenkins hadoop elastic es kafka redis
		docker ansible deploy deployer dev developer devops demo support info sales operator service system sysadmin backup nagios
		zabbix minecraft steam ts3 teamspeak sol solana validator node nodejs user1 user2 ubnt admin1 oracle1 postgres1 odoo
		vagrant azureuser cloud cloud-user debian-user opc oper default master manager office temp tmp a test123 student web
		web1 webmaster wordpress wp mail email postfix sftp ssh nobody daemon bin sys sync games man lp news uucp proxy list irc
		gnats systemd-network _apt sshd ubuntu1 bitnami pgsql gpadmin hduser spark elasticsearch flink zookeeper esuser mongo
		mongodb ethereum bitcoin geth trader admin123 adm usuario usr alex john david michael`) {
		commonUsers[u] = true
	}
}

// ownTokens are words from the host names and the dashboard's brand: an
// attacker who tries them knows whom they are attacking.
func (s *Server) ownTokens() []string {
	s.mu.Lock()
	var names []string
	for _, a := range s.state.Agents {
		names = append(names, a.Name)
	}
	s.mu.Unlock()
	if s.cfg.Brand != nil {
		names = append(names, s.cfg.Brand.Name)
	}
	generic := map[string]bool{"server": true, "host": true, "prod": true, "test": true, "main": true, "node": true, "game": true,
		"gameserver": true, "webserver": true, "web": true, "vigil": true, "localhost": true, "ubuntu": true, "debian": true,
		"vps": true, "cloud": true, "staging": true, "backup": true, "mail": true, "admin": true}
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		for _, w := range strings.FieldsFunc(strings.ToLower(n), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
			if len(w) >= 4 && !generic[w] && !seen[w] && !commonUsers[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	return out
}

// attackWindow merges the days of the window. The caller holds r.mu.
// userWindow holds the attempts per user over the window. It comes from the
// day's per-user hours, which also count the few failed tries of the team's
// own addresses (a key offered in the wrong order); the per-address views
// leave those out.
type userWindow struct {
	days  map[string][]int
	hours map[string]*[24]int
	est   bool
}

// attackWindow merges the last days. With hit, only the addresses it
// accepts count, and the hour and user tables (kept per day, not per
// address) stay empty.
func (r *attackRollup) attackWindow(days int, now time.Time, hit ...func(*atkIP) bool) (map[string]*atkIP, map[string]int, []dayStat, [24]int, int, userWindow) {
	var keep func(*atkIP) bool
	if len(hit) > 0 {
		keep = hit[0]
	}
	uw := userWindow{days: map[string][]int{}, hours: map[string]*[24]int{}}
	merged := map[string]*atkIP{}
	active := map[string]int{}
	var hours [24]int
	var per []dayStat
	overflow := 0
	for i := days - 1; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		ds := dayStat{Day: day}
		if d := r.days[day]; d != nil {
			for ip, x := range d.IPs {
				if keep != nil && !keep(x) {
					continue
				}
				if x.attempts() > 0 {
					ds.IPs++
					active[ip]++
				}
				ds.SSH += x.SSH
				ds.Web += x.Web
				m := merged[ip]
				if m == nil {
					m = &atkIP{}
					merged[ip] = m
				}
				mergeIP(m, x)
			}
			if keep != nil {
				per = append(per, ds)
				continue
			}
			for h, n := range d.Hours {
				hours[h] += n
			}
			overflow += d.Overflow
			idx := days - 1 - i
			for u, hr := range d.UH {
				dd := uw.days[u]
				if dd == nil {
					dd = make([]int, days)
					uw.days[u] = dd
				}
				uh := uw.hours[u]
				if uh == nil {
					uh = &[24]int{}
					uw.hours[u] = uh
				}
				for h, n := range hr {
					dd[idx] += n
					uh[h] += n
				}
			}
			uw.est = uw.est || d.Est
		}
		per = append(per, ds)
	}
	return merged, active, per, hours, overflow, uw
}

// attackStats builds the view for the last days (1 to 30), cached for a
// minute.
func (s *Server) attackStats(days int) *attackView { return s.attackStatsFor(days, "") }

func (s *Server) attackStatsFor(days int, agent string) *attackView {
	if days < 1 {
		days = 1
	}
	if days > attackDaysMax {
		days = attackDaysMax
	}
	r := &s.attacks
	r.mu.Lock()
	key := strconv.Itoa(days) + "|" + agent
	if c, ok := r.cache[key]; ok && time.Since(c.at) < time.Minute {
		r.mu.Unlock()
		return c.v
	}
	r.mu.Unlock()
	names := s.agentNames()
	own := s.ownTokens()
	now := time.Now().UTC()
	r.mu.Lock()
	ready := r.ready
	var hit []func(*atkIP) bool
	if agent != "" {
		hit = append(hit, func(x *atkIP) bool {
			for _, h := range x.Hosts {
				if h == agent {
					return true
				}
			}
			return false
		})
	}
	merged, active, per, hours, overflow, uw := r.attackWindow(days, now, hit...)
	r.mu.Unlock()

	v := &attackView{Days: days, Agent: agent, Ready: ready, Generated: now, PerDay: per, Hours: hours, NetKinds: map[string]int{}, Geo: s.geoStatus(),
		all: map[string]*addrView{}}
	v.Totals.Overflow = overflow
	v.Estimated = uw.est
	userCC := map[string]map[string]bool{}
	cellCount := map[[2]string]int{}
	flowCount := map[flow]int{}
	userIPs := map[string]int{}
	userExisting := map[string]bool{}
	pathIPs := map[string]int{}
	kindIPs := map[string]int{}
	countries := map[string]*geoCount{}
	nets := map[uint32]*netCount{}
	netCC := map[uint32]map[string]int{} // a network's addresses per country
	var list []*addrView
	for ip, x := range merged {
		if x.attempts() == 0 || x.own() {
			continue
		}
		for _, u := range x.Users {
			userIPs[u]++
		}
		for _, u := range x.Existing {
			userExisting[u] = true
		}
		for _, p := range x.Paths {
			pathIPs[p]++
		}
		for _, k := range x.Kinds {
			kindIPs[k]++
		}
		g := s.geo(ip)
		cc := g.Country
		if cc == "" {
			cc = "??"
		}
		for u, n := range x.UC {
			if userCC[u] == nil {
				userCC[u] = map[string]bool{}
			}
			userCC[u][cc] = true
			cellCount[[2]string{u, cc}] += n
			flowCount[flow{Country: cc, User: u}] += n
		}
		av := &addrView{IP: ip, GeoInfo: g, SSH: x.SSH, Web: x.Web, Users: x.Users, Existing: x.Existing, Paths: x.Paths, Kinds: x.Kinds,
			Logins: x.Logins, LoginAs: x.LoginUsers, ExploitOK: x.ExploitOK, Shells: x.Shells, UA: x.UA, First: x.First, Last: x.Last,
			Days: active[ip], Campaign: -1}
		for _, h := range x.Hosts {
			if n := names[h]; n != "" {
				av.Hosts = append(av.Hosts, n)
			}
		}
		sort.Strings(av.Hosts)
		if list, ok := s.intel.lookup(ip); ok {
			av.Listed = list
		}
		c := countries[cc]
		if c == nil {
			c = &geoCount{Key: cc}
			countries[cc] = c
		}
		c.IPs++
		c.Count += x.attempts()
		if g.ASN != 0 {
			n := nets[g.ASN]
			if n == nil {
				n = &netCount{ASN: g.ASN, Org: g.Org, Net: g.Net}
				nets[g.ASN] = n
				netCC[g.ASN] = map[string]int{}
			}
			n.IPs++
			n.Count += x.attempts()
			netCC[g.ASN][g.Country]++
		}
		kind := g.Net
		if kind == "" {
			kind = "other"
		}
		v.NetKinds[kind]++
		v.Totals.SSH += x.SSH
		v.Totals.Web += x.Web
		list = append(list, av)
		v.all[ip] = av
	}
	v.Totals.IPs = len(list)
	v.Totals.Countries = len(countries)
	if countries["??"] != nil {
		v.Totals.Countries--
	}
	v.Totals.Networks = len(nets)

	v.Campaigns = findCampaigns(list, merged)
	for i := range v.Campaigns {
		for _, ip := range v.Campaigns[i].Members {
			v.all[ip].Campaign = i
		}
	}
	for _, av := range list {
		classify(av, userIPs, own, len(v.Campaigns) > 0 && av.Campaign >= 0)
		switch av.Class {
		case "success":
			v.Totals.Success++
		case "targeted":
			v.Totals.Targeted++
		case "persistent":
			v.Totals.Persistent++
		default:
			v.Totals.Noise++
		}
	}
	v.Totals.Campaigns = len(v.Campaigns)

	rank := map[string]int{"success": 0, "targeted": 1, "persistent": 2, "noise": 3}
	sort.Slice(list, func(i, j int) bool {
		if rank[list[i].Class] != rank[list[j].Class] {
			return rank[list[i].Class] < rank[list[j].Class]
		}
		if list[i].attempts() != list[j].attempts() {
			return list[i].attempts() > list[j].attempts()
		}
		return list[i].IP < list[j].IP
	})
	for i, av := range list {
		if i >= 300 {
			break
		}
		v.Addresses = append(v.Addresses, *av)
	}
	if v.Addresses == nil {
		v.Addresses = []addrView{}
	}
	for _, c := range countries {
		v.Countries = append(v.Countries, *c)
	}
	sort.Slice(v.Countries, func(i, j int) bool {
		if v.Countries[i].Count != v.Countries[j].Count {
			return v.Countries[i].Count > v.Countries[j].Count
		}
		return v.Countries[i].Key < v.Countries[j].Key
	})
	for asn, n := range nets {
		// the country most of its attacking addresses are in
		if top := topCounts(netCC[asn], 1); len(top) == 1 {
			n.Country = top[0].Key
		}
		v.Networks = append(v.Networks, *n)
	}
	sort.Slice(v.Networks, func(i, j int) bool {
		if v.Networks[i].IPs != v.Networks[j].IPs {
			return v.Networks[i].IPs > v.Networks[j].IPs
		}
		return v.Networks[i].ASN < v.Networks[j].ASN
	})
	if len(v.Networks) > 20 {
		v.Networks = v.Networks[:20]
	}
	if v.Networks == nil {
		v.Networks = []netCount{}
	}
	if v.Countries == nil {
		v.Countries = []geoCount{}
	}
	for u, n := range userIPs {
		v.Users = append(v.Users, userCount{User: u, IPs: n, Existing: userExisting[u]})
	}
	sort.Slice(v.Users, func(i, j int) bool {
		if v.Users[i].IPs != v.Users[j].IPs {
			return v.Users[i].IPs > v.Users[j].IPs
		}
		return v.Users[i].User < v.Users[j].User
	})
	if len(v.Users) > 25 {
		v.Users = v.Users[:25]
	}
	if v.Users == nil {
		v.Users = []userCount{}
	}
	// an account exists or not per host, whichever address tried it
	flows := map[flow]int{}
	for f, n := range flowCount {
		f.Existing = userExisting[f.User]
		flows[f] += n
	}
	v.UserStats, v.Matrix, v.Flows = userViews(uw, userIPs, userExisting, userCC, cellCount, flows)
	v.Paths = topCounts(pathIPs, 15)
	v.WebKinds = topCounts(kindIPs, 10)
	if v.Campaigns == nil {
		v.Campaigns = []campaignView{}
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]attackCache{}
	}
	r.cache[key] = attackCache{time.Now(), v}
	r.mu.Unlock()
	return v
}

func (a *addrView) attempts() int { return a.SSH + a.Web }

const (
	userStatsMax    = 60 // the word cloud; the table shows the first ones
	matrixUsers     = 12
	matrixCountries = 8
	flowCountries   = 6
	flowUsers       = 10
	otherKey        = "*" // the rest, folded into one row or band
)

// userViews builds the per-user statistics, the user by country matrix and
// the bands from country to user to account. Users are ranked by attempts.
func userViews(uw userWindow, userIPs map[string]int, existing map[string]bool, userCC map[string]map[string]bool,
	cells map[[2]string]int, flows map[flow]int) ([]userStat, userMatrix, []flow) {
	stats := []userStat{}
	for u, dd := range uw.days {
		st := userStat{User: u, IPs: userIPs[u], Countries: len(userCC[u]), Existing: existing[u], Days: dd}
		if h := uw.hours[u]; h != nil {
			st.Hours = *h
		}
		for _, n := range dd {
			st.Attempts += n
		}
		if st.Attempts > 0 {
			stats = append(stats, st)
		}
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Attempts != stats[j].Attempts {
			return stats[i].Attempts > stats[j].Attempts
		}
		return stats[i].User < stats[j].User
	})
	if len(stats) > userStatsMax {
		stats = stats[:userStatsMax]
	}

	ccTotal := map[string]int{}
	for k, n := range cells {
		ccTotal[k[1]] += n
	}
	rank := func(m map[string]int, n int) []string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if m[keys[i]] != m[keys[j]] {
				return m[keys[i]] > m[keys[j]]
			}
			return keys[i] < keys[j]
		})
		if len(keys) > n {
			keys = keys[:n]
		}
		return keys
	}
	mx := userMatrix{Users: []string{}, Countries: rank(ccTotal, matrixCountries), Cells: [][]int{}}
	for i := 0; i < len(stats) && i < matrixUsers; i++ {
		u := stats[i].User
		row := make([]int, len(mx.Countries))
		for j, cc := range mx.Countries {
			row[j] = cells[[2]string{u, cc}]
		}
		mx.Users = append(mx.Users, u)
		mx.Cells = append(mx.Cells, row)
	}

	topCC := map[string]bool{}
	for _, cc := range rank(ccTotal, flowCountries) {
		topCC[cc] = true
	}
	topUser := map[string]bool{}
	for i := 0; i < len(stats) && i < flowUsers; i++ {
		topUser[stats[i].User] = true
	}
	folded := map[flow]int{}
	for f, n := range flows {
		if !topCC[f.Country] {
			f.Country = otherKey
		}
		if !topUser[f.User] {
			f.User = otherKey
		}
		folded[f] += n
	}
	out := []flow{}
	for f, n := range folded {
		f.Count = n
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return fmt.Sprint(out[i]) < fmt.Sprint(out[j])
	})
	return stats, mx, out
}

func topCounts(m map[string]int, n int) []geoCount {
	out := []geoCount{}
	for k, c := range m {
		out = append(out, geoCount{Key: k, IPs: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IPs != out[j].IPs {
			return out[i].IPs > out[j].IPs
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// classify decides how aimed an address is:
//   - success: it logged in over SSH after failing, or an attack request
//     was answered with 2xx or reached a web shell
//   - targeted: it tried accounts this host really has that are in no word
//     list, or names from the host names or the brand, and never root:
//     root is in every word list, so whoever tries it works through one
//   - persistent: it came back on three or more days
//   - noise: everything else, mass scanning that every server gets
func classify(av *addrView, userIPs map[string]int, own []string, inCampaign bool) {
	var reasons []string
	if av.Logins > 0 && av.SSH > 0 {
		reasons = append(reasons, "login")
	}
	if av.ExploitOK > 0 || av.Shells > 0 {
		reasons = append(reasons, "web_ok")
	}
	for _, u := range av.Existing {
		if !commonUsers[strings.ToLower(u)] && userIPs[u] <= 2 {
			reasons = append(reasons, "own_account")
			break
		}
	}
	found := false
	for _, w := range own {
		for _, u := range av.Users {
			if strings.Contains(strings.ToLower(u), w) {
				found = true
			}
		}
		for _, p := range av.Paths {
			if strings.Contains(strings.ToLower(p), w) {
				found = true
			}
		}
	}
	if found {
		reasons = append(reasons, "own_name")
	}
	if av.Days >= 3 && av.attempts() >= 20 {
		reasons = append(reasons, "persistent")
	}
	if av.Listed != "" {
		reasons = append(reasons, "listed")
	}
	if av.Net == "tor" {
		reasons = append(reasons, "tor")
	}
	if inCampaign {
		reasons = append(reasons, "campaign")
	}
	words := len(av.Users) > 0
	for _, u := range av.Users {
		if !commonUsers[strings.ToLower(u)] && userIPs[u] < 3 {
			words = false
		}
	}
	if words {
		reasons = append(reasons, "wordlist")
	}
	for _, u := range av.Users {
		if strings.ToLower(u) == "root" {
			reasons = append(reasons, "root")
			break
		}
	}
	has := func(k string) bool {
		for _, r := range reasons {
			if r == k {
				return true
			}
		}
		return false
	}
	switch {
	case has("login") || has("web_ok"):
		av.Class = "success"
	case (has("own_account") || has("own_name")) && !has("root"):
		av.Class = "targeted"
	case has("persistent"):
		av.Class = "persistent"
	default:
		av.Class = "noise"
	}
	av.Reasons = reasons
}

// findCampaigns groups addresses that try the same things: the same user
// names or paths, at least three of them, with a Jaccard similarity of 0.6
// or more. Botnets work through one list from many addresses; seen as a
// group they are one attacker, not hundreds.
func findCampaigns(list []*addrView, merged map[string]*atkIP) []campaignView {
	type member struct {
		ip     string
		tokens map[string]bool
	}
	var ms []member
	for _, av := range list {
		x := merged[av.IP]
		t := map[string]bool{}
		for _, u := range x.Users {
			t["u:"+u] = true
		}
		for _, p := range x.Paths {
			t["p:"+p] = true
		}
		if len(t) >= 3 {
			ms = append(ms, member{av.IP, t})
		}
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].ip < ms[j].ip })
	index := map[string][]int{}
	for i, m := range ms {
		for t := range m.tokens {
			index[t] = append(index[t], i)
		}
	}
	parent := make([]int, len(ms))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	checked := map[[2]int]bool{}
	budget := 2_000_000 // comparisons; enough for tens of thousands of addresses
	for _, idx := range index {
		if len(idx) < 2 || len(idx) > 400 {
			continue // a token everyone tries links nothing
		}
		for a := 0; a < len(idx) && budget > 0; a++ {
			for b := a + 1; b < len(idx) && budget > 0; b++ {
				i, j := idx[a], idx[b]
				if checked[[2]int{i, j}] || find(i) == find(j) {
					continue
				}
				checked[[2]int{i, j}] = true
				budget--
				inter := 0
				for t := range ms[i].tokens {
					if ms[j].tokens[t] {
						inter++
					}
				}
				union := len(ms[i].tokens) + len(ms[j].tokens) - inter
				if inter >= 3 && float64(inter)/float64(union) >= 0.6 {
					parent[find(i)] = find(j)
				}
			}
		}
	}
	groups := map[int][]int{}
	for i := range ms {
		groups[find(i)] = append(groups[find(i)], i)
	}
	byIP := map[string]*addrView{}
	for _, av := range list {
		byIP[av.IP] = av
	}
	var out []campaignView
	for _, g := range groups {
		if len(g) < 3 {
			continue
		}
		c := campaignView{Size: len(g)}
		tok := map[string]int{}
		cc := map[string]int{}
		asn := map[uint32]bool{}
		hosts := map[string]bool{}
		ssh, web := false, false
		for _, i := range g {
			av := byIP[ms[i].ip]
			c.Members = append(c.Members, av.IP)
			c.Attempts += av.attempts()
			ssh = ssh || av.SSH > 0
			web = web || av.Web > 0
			for t := range ms[i].tokens {
				tok[t]++
			}
			k := av.Country
			if k == "" {
				k = "??"
			}
			cc[k]++
			if av.ASN != 0 {
				asn[av.ASN] = true
			}
			for _, h := range av.Hosts {
				hosts[h] = true
			}
			if c.First.IsZero() || av.First.Before(c.First) {
				c.First = av.First
			}
			if av.Last.After(c.Last) {
				c.Last = av.Last
			}
		}
		c.Kind = map[[2]bool]string{{true, false}: "ssh", {false, true}: "web", {true, true}: "both"}[[2]bool{ssh, web}]
		for _, t := range topCounts(tok, 8) {
			c.Signature = append(c.Signature, t.Key)
		}
		for _, x := range topCounts(cc, 6) {
			c.Countries = append(c.Countries, geoCount{Key: x.Key, IPs: x.IPs})
		}
		c.Networks = len(asn)
		for h := range hosts {
			c.Hosts = append(c.Hosts, h)
		}
		sort.Strings(c.Hosts)
		sort.Slice(c.Members, func(i, j int) bool { return byIP[c.Members[i]].attempts() > byIP[c.Members[j]].attempts() })
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Size != out[j].Size {
			return out[i].Size > out[j].Size
		}
		return out[i].Members[0] < out[j].Members[0]
	})
	if len(out) > 30 {
		out = out[:30]
	}
	for i := range out {
		out[i].ID = i
	}
	return out
}

// attackProfile is what the pivot page shows about an address: its view
// over 30 days with origin and class, and its activity per day.
func (s *Server) attackProfile(ip string) map[string]any {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	ip = a.Unmap().String()
	out := map[string]any{"geo": s.geo(ip), "attribution": GeoAttribution, "attribution_url": GeoAttributionURL, "geoip": s.cfg.GeoIP}
	v := s.attackStats(attackDaysMax)
	if av := v.all[ip]; av != nil {
		cp := *av
		out["attack"] = cp
		if cp.Campaign >= 0 && cp.Campaign < len(v.Campaigns) {
			c := v.Campaigns[cp.Campaign]
			if len(c.Members) > 25 {
				c.Members = c.Members[:25]
			}
			out["campaign"] = c
		}
	}
	r := &s.attacks
	now := time.Now().UTC()
	var per []dayStat
	r.mu.Lock()
	for i := attackDaysMax - 1; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		ds := dayStat{Day: day}
		if d := r.days[day]; d != nil {
			if x := d.IPs[ip]; x != nil {
				ds.SSH, ds.Web = x.SSH, x.Web
			}
		}
		per = append(per, ds)
	}
	r.mu.Unlock()
	out["per_day"] = per
	return out
}

// failedBefore counts the failed SSH logins of an address over the last
// days and returns the users it tried (for ssh.attacker_login).
func (s *Server) failedBefore(ip string, days int) (int, []string) {
	r := &s.attacks
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.days == nil {
		return 0, nil
	}
	n := 0
	var users []string
	now := time.Now().UTC()
	for i := 0; i < days; i++ {
		if d := r.days[now.AddDate(0, 0, -i).Format("2006-01-02")]; d != nil {
			if x := d.IPs[ip]; x != nil {
				n += x.SSH
				for _, u := range x.Users {
					users = addUnique(users, u, 50)
				}
			}
		}
	}
	return n, users
}

// liveAttack is one attack record for the live map.
type liveAttack struct {
	Seq     uint64    `json:"seq"`
	Time    time.Time `json:"time"`
	IP      string    `json:"ip"`
	Country string    `json:"country,omitempty"`
	Host    string    `json:"host,omitempty"`
	Kind    string    `json:"kind"` // ssh | web
	Count   int       `json:"count"`
	Users   []string  `json:"users,omitempty"`
}

// GET /api/ui/attacks/live?after=SEQ: attack records newer than SEQ from
// the in-memory window, oldest first, at most 200. Without after, only the
// cursor is returned, so a new viewer starts with what comes next.
func (s *Server) handleAttacksLive(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	after, _ := strconv.ParseUint(q.Get("after"), 10, 64)
	head, _ := s.store.Head()
	out := []liveAttack{}
	if q.Has("after") {
		names := s.agentNames()
		s.store.Each(func(rec Record) {
			// records after head come again with the next cursor
			if rec.Seq <= after || rec.Seq > head || len(out) >= 200 {
				return
			}
			d := rec.Event.Data
			la := liveAttack{Seq: rec.Seq, Time: recordTime(rec).UTC(), IP: str(d, "ip"), Host: names[rec.Agent]}
			switch rec.Event.Type {
			case "ssh.failed":
				la.Kind, la.Count = "ssh", int(num(d, "count"))
				la.Users = strSlice(d["users"])
				if len(la.Users) > 5 {
					la.Users = la.Users[:5]
				}
			case "web.activity":
				if num(d, "probes")+num(d, "exploits_ok")+num(d, "shells") == 0 {
					return
				}
				la.Kind, la.Count = "web", int(num(d, "requests"))
			default:
				return
			}
			a, err := netip.ParseAddr(la.IP)
			if err != nil || a.IsLoopback() || a.IsPrivate() || la.Count <= 0 {
				return
			}
			la.Country = s.geo(la.IP).Country
			out = append(out, la)
		})
		out = s.dropOwn(out)
	}
	writeJSON(w, map[string]any{"cursor": head, "attacks": out, "home": s.cfg.MapHome})
}

// dropOwn leaves out the team's addresses (see atkIP.own).
func (s *Server) dropOwn(list []liveAttack) []liveAttack {
	r := &s.attacks
	r.mu.Lock()
	defer r.mu.Unlock()
	day := r.days[time.Now().UTC().Format("2006-01-02")]
	kept := list[:0]
	for _, la := range list {
		if day != nil {
			if x := day.IPs[la.IP]; x != nil && x.own() {
				continue
			}
		}
		kept = append(kept, la)
	}
	return kept
}

// GET /api/ui/attacks?days=1|7|30
func (s *Server) handleAttacks(w http.ResponseWriter, r *http.Request, sess *session) {
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
	writeJSON(w, s.attackStatsFor(days, agent))
}

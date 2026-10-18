package server

import (
	"encoding/json"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Attack statistics: who attacks the hosts, from where, with what, and
// whether it is aimed at them. The server keeps one small rollup per day
// (address, attempts, tried users and paths, success) built from failed SSH
// logins, flagged web requests and SSH logins. Past days are kept as files
// in data_dir/attacks, so views over 30 days never rescan the log; the
// current day is rebuilt from the log at start and then follows new records.
// Where an address comes from is looked up when a view is built and never
// written into the chained log.

const (
	attackDaysMax   = 30
	attackIPsPerDay = 50000
	attackUsersMax  = 20
	attackPathsMax  = 12
)

type atkIP struct {
	SSH        int       `json:"s,omitempty"`  // failed SSH attempts
	Web        int       `json:"w,omitempty"`  // flagged web requests
	Probes     int       `json:"p,omitempty"`  // requests for typical attack paths
	ExploitOK  int       `json:"x,omitempty"`  // attack requests the server answered with 2xx
	Shells     int       `json:"sh,omitempty"` // requests to web shells
	WebLogins  int       `json:"wl,omitempty"` // login form posts
	Logins     int       `json:"l,omitempty"`  // successful SSH logins
	LoginUsers []string  `json:"lu,omitempty"`
	Users      []string  `json:"u,omitempty"` // tried SSH users
	Existing   []string  `json:"e,omitempty"` // tried users the host has an account for
	Paths      []string  `json:"pa,omitempty"`
	Kinds      []string  `json:"k,omitempty"` // web attack kinds
	UA         string    `json:"ua,omitempty"`
	Hosts      []string  `json:"h,omitempty"` // agent IDs
	First      time.Time `json:"f"`
	Last       time.Time `json:"t"`
}

func (x *atkIP) attempts() int { return x.SSH + x.Web }

type atkDay struct {
	Day      string            `json:"day"`
	IPs      map[string]*atkIP `json:"ips"`
	Hours    [24]int           `json:"hours"` // attempts per UTC hour
	Overflow int               `json:"overflow,omitempty"`
	saved    bool
}

type attackRollup struct {
	mu    sync.Mutex
	dir   string
	days  map[string]*atkDay
	upTo  uint64 // records up to this seq are counted by the build at start
	ready bool
	cache map[int]attackCache
}

func addUnique(list []string, v string, max int) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	if len(list) >= max {
		return list
	}
	return append(list, v)
}

// add counts one record. The caller holds r.mu.
func (r *attackRollup) add(rec Record) {
	var ip string
	switch rec.Event.Type {
	case "ssh.failed", "web.activity", "ssh.login":
		ip = str(rec.Event.Data, "ip")
	default:
		return
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || a.IsLoopback() || a.IsUnspecified() {
		return
	}
	ip = a.Unmap().String()
	t := recordTime(rec).UTC()
	day := t.Format("2006-01-02")
	if time.Since(t) > (attackDaysMax+1)*24*time.Hour || t.After(time.Now().Add(time.Hour)) {
		return
	}
	d := r.days[day]
	if d == nil {
		d = &atkDay{Day: day, IPs: map[string]*atkIP{}}
		r.days[day] = d
	}
	d.saved = false // a late record: write the day again
	x := d.IPs[ip]
	if x == nil {
		if len(d.IPs) >= attackIPsPerDay {
			d.Overflow++
			return
		}
		x = &atkIP{First: t, Last: t}
		d.IPs[ip] = x
	}
	if t.Before(x.First) {
		x.First = t
	}
	if t.After(x.Last) {
		x.Last = t
	}
	if rec.Agent != "" {
		x.Hosts = addUnique(x.Hosts, rec.Agent, 50)
	}
	dd := rec.Event.Data
	switch rec.Event.Type {
	case "ssh.failed":
		n := int(num(dd, "count"))
		x.SSH += n
		d.Hours[t.Hour()] += n
		for _, u := range strSlice(dd["users"]) {
			x.Users = addUnique(x.Users, u, attackUsersMax)
		}
		for _, u := range strSlice(dd["existing_users"]) {
			x.Existing = addUnique(x.Existing, u, attackUsersMax)
		}
	case "web.activity":
		n := int(num(dd, "requests"))
		x.Web += n
		d.Hours[t.Hour()] += n
		x.Probes += int(num(dd, "probes"))
		x.ExploitOK += int(num(dd, "exploits_ok"))
		x.Shells += int(num(dd, "shells"))
		x.WebLogins += int(num(dd, "logins"))
		for _, k := range strSlice(dd["exploit_kinds"]) {
			x.Kinds = addUnique(x.Kinds, k, 10)
		}
		for _, sm := range strSlice(dd["samples"]) {
			if f := strings.Fields(sm); len(f) > 0 {
				p := f[len(f)-1]
				if i := strings.IndexByte(p, '?'); i > 0 {
					p = p[:i]
				}
				x.Paths = addUnique(x.Paths, clip(p, 120), attackPathsMax)
			}
		}
		if ua := str(dd, "user_agent"); ua != "" && x.UA == "" {
			x.UA = clip(ua, 200)
		}
	case "ssh.login":
		x.Logins++
		x.LoginUsers = addUnique(x.LoginUsers, str(dd, "user"), 10)
	}
}

type attackCache struct {
	at time.Time
	v  *attackView
}

// onRecords follows new records (store hook).
func (r *attackRollup) onRecords(recs []*Record) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.days == nil {
		return
	}
	for _, rec := range recs {
		if rec.Seq > r.upTo {
			r.add(*rec)
		}
	}
}

// startAttacks loads the saved days and rebuilds the missing ones from the
// log. New records are followed from the moment it is called.
func (s *Server) startAttacks() {
	r := &s.attacks
	r.dir = filepath.Join(s.cfg.DataDir, "attacks")
	os.MkdirAll(r.dir, 0o700)
	r.mu.Lock()
	r.days = map[string]*atkDay{}
	r.upTo, _ = s.store.Head()
	r.mu.Unlock()
	s.store.hooks = append(s.store.hooks, r.onRecords)
	go func() {
		start := time.Now()
		now := time.Now().UTC()
		today := now.Format("2006-01-02")
		days := attackDaysMax
		if s.cfg.RetentionDays > 0 && s.cfg.RetentionDays < days {
			days = s.cfg.RetentionDays
		}
		missing := map[string]bool{}
		var from time.Time
		for i := days; i >= 0; i-- {
			t := now.AddDate(0, 0, -i)
			day := t.Format("2006-01-02")
			if day != today {
				if d := loadAttackDay(r.dir, day); d != nil {
					r.mu.Lock()
					r.merge(d)
					r.mu.Unlock()
					continue
				}
			}
			if from.IsZero() {
				from = t
			}
			missing[day] = true
		}
		// Between reads a day of margin around the range; each record counts
		// for the day it happened on, and only for days not loaded.
		s.store.Between(from, now, func(rec Record) bool {
			if rec.Seq > r.upTo || !missing[recordTime(rec).UTC().Format("2006-01-02")] {
				return true
			}
			r.mu.Lock()
			r.add(rec)
			r.mu.Unlock()
			return true
		})
		r.mu.Lock()
		r.ready = true
		r.cache = nil
		r.mu.Unlock()
		r.persist()
		log.Printf("attacks: %d days ready in %s (%d rebuilt from the log)", days+1, time.Since(start).Round(time.Millisecond), len(missing))
	}()
}

// merge adds a loaded day to the in-memory one (records that arrived
// while loading). The caller holds r.mu.
func (r *attackRollup) merge(d *atkDay) {
	cur := r.days[d.Day]
	d.saved = true
	if cur == nil {
		r.days[d.Day] = d
		return
	}
	for ip, x := range cur.IPs {
		if y := d.IPs[ip]; y != nil {
			mergeIP(y, x)
		} else {
			d.IPs[ip] = x
		}
	}
	for i := range cur.Hours {
		d.Hours[i] += cur.Hours[i]
	}
	r.days[d.Day] = d
}

func mergeIP(into, x *atkIP) {
	into.SSH += x.SSH
	into.Web += x.Web
	into.Probes += x.Probes
	into.ExploitOK += x.ExploitOK
	into.Shells += x.Shells
	into.WebLogins += x.WebLogins
	into.Logins += x.Logins
	for _, l := range [][2]*[]string{{&into.LoginUsers, &x.LoginUsers}, {&into.Users, &x.Users}, {&into.Existing, &x.Existing},
		{&into.Paths, &x.Paths}, {&into.Kinds, &x.Kinds}, {&into.Hosts, &x.Hosts}} {
		max := attackUsersMax
		if l[0] == &into.Paths {
			max = attackPathsMax
		}
		for _, v := range *l[1] {
			*l[0] = addUnique(*l[0], v, max)
		}
	}
	if into.UA == "" {
		into.UA = x.UA
	}
	if into.First.IsZero() || !x.First.IsZero() && x.First.Before(into.First) {
		into.First = x.First
	}
	if x.Last.After(into.Last) {
		into.Last = x.Last
	}
}

func loadAttackDay(dir, day string) *atkDay {
	b, err := os.ReadFile(filepath.Join(dir, day+".json"))
	if err != nil {
		return nil
	}
	var d atkDay
	if json.Unmarshal(b, &d) != nil || d.Day != day {
		return nil
	}
	if d.IPs == nil {
		d.IPs = map[string]*atkIP{}
	}
	return &d
}

// persist writes finished days and forgets days past the window. Called
// after the start and every hour.
func (r *attackRollup) persist() {
	r.mu.Lock()
	if !r.ready {
		r.mu.Unlock()
		return
	}
	today := time.Now().UTC().Format("2006-01-02")
	oldest := time.Now().UTC().AddDate(0, 0, -attackDaysMax).Format("2006-01-02")
	var write []*atkDay
	for day, d := range r.days {
		if day < oldest {
			delete(r.days, day)
			continue
		}
		if day < today && !d.saved {
			d.saved = true
			write = append(write, d)
		}
	}
	// Encode under the lock: late records may still change a day.
	files := map[string][]byte{}
	for _, d := range write {
		if b, err := json.Marshal(d); err == nil {
			files[d.Day] = b
		}
	}
	r.mu.Unlock()
	for day, b := range files {
		tmp := filepath.Join(r.dir, day+".json.tmp")
		if err := os.WriteFile(tmp, b, 0o600); err == nil {
			os.Rename(tmp, filepath.Join(r.dir, day+".json"))
		}
	}
	if ents, err := os.ReadDir(r.dir); err == nil {
		for _, e := range ents {
			if name := e.Name(); strings.HasSuffix(name, ".json") && name < oldest {
				os.Remove(filepath.Join(r.dir, name))
			}
		}
	}
}

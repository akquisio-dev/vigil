package server

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

//go:embed web
var webFS embed.FS

const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.ServeHTTP(w, r)
	})
}

type authed func(w http.ResponseWriter, r *http.Request, sess *session)

// auth lets any signed-in user through; analyst and admin need that role.
// The user file is checked on every request, so a removed user or a lowered
// role takes effect at once.
func (s *Server) auth(h authed) http.HandlerFunc      { return s.authRole("viewer", h) }
func (s *Server) analyst(h authed) http.HandlerFunc   { return s.authRole("analyst", h) }
func (s *Server) adminOnly(h authed) http.HandlerFunc { return s.authRole("admin", h) }

func (s *Server) authRole(role string, h authed) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFor(r)
		if sess == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		u := s.user(sess.User)
		if u == nil {
			s.endSessions(sess.User, nil)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-CSRF") != sess.CSRF {
			http.Error(w, "csrf", http.StatusForbidden)
			return
		}
		if roleRank[roleOf(u)] < roleRank[role] {
			http.Error(w, "your role ("+roleOf(u)+") does not allow this", http.StatusForbidden)
			return
		}
		h(w, r, sess)
	}
}

func (s *Server) meJSON(sess *session) map[string]any {
	role := "viewer"
	if u := s.user(sess.User); u != nil {
		role = roleOf(u)
	}
	return map[string]any{"user": sess.User, "csrf": sess.CSRF, "version": Version, "agent_url": s.cfg.AgentURL, "role": role}
}

func (s *Server) uiHandler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	index, version := versionedIndex(static)
	index, brand, err := applyBrand(index, s.cfg.Brand)
	if err != nil {
		log.Printf("brand: %v; using the vigil logo", err)
	}
	files := http.FileServerFS(static)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/brand-icon.svg" && brand.icon != "" {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			w.Write([]byte(brand.icon))
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.Write(index)
			return
		}
		// Assets are addressed with ?v=<content hash>, so caches (a CDN in
		// front of the dashboard included) never mix old and new files.
		if r.URL.Query().Get("v") == version || strings.HasPrefix(r.URL.Path, "/fonts/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})

	mux.HandleFunc("POST /api/ui/login", s.handleLogin)
	mux.HandleFunc("POST /api/ui/logout", s.auth(func(w http.ResponseWriter, r *http.Request, sess *session) {
		s.logout(r)
		s.setCookie(w, "", -1)
		s.audit(sess.User, "admin.logout", nil)
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/ui/me", s.auth(func(w http.ResponseWriter, r *http.Request, sess *session) {
		writeJSON(w, s.meJSON(sess))
	}))
	mux.HandleFunc("POST /api/ui/passkey/begin", s.handlePasskeyLoginBegin)
	mux.HandleFunc("POST /api/ui/passkey/finish", s.handlePasskeyLoginFinish)
	mux.HandleFunc("GET /api/ui/account", s.auth(s.handleAccount))
	mux.HandleFunc("POST /api/ui/account/password", s.auth(s.handlePassword))
	mux.HandleFunc("POST /api/ui/account/passkeys/begin", s.auth(s.handlePasskeyBegin))
	mux.HandleFunc("POST /api/ui/account/passkeys/finish", s.auth(s.handlePasskeyFinish))
	mux.HandleFunc("POST /api/ui/account/passkeys/{id}/delete", s.auth(s.handlePasskeyDelete))
	mux.HandleFunc("GET /api/ui/users", s.adminOnly(s.handleUsers))
	mux.HandleFunc("POST /api/ui/users", s.adminOnly(s.handleUserCreate))
	mux.HandleFunc("POST /api/ui/users/{name}/{action}", s.adminOnly(s.handleUserAction))
	mux.HandleFunc("GET /api/ui/overview", s.auth(s.handleOverview))
	mux.HandleFunc("GET /api/ui/alerts", s.auth(s.handleAlerts))
	mux.HandleFunc("POST /api/ui/alerts/{id}/{action}", s.analyst(s.handleAlertAction))
	mux.HandleFunc("GET /api/ui/events", s.auth(s.handleEventsList))
	mux.HandleFunc("GET /api/ui/timeline", s.auth(s.handleTimeline))
	mux.HandleFunc("GET /api/ui/records", s.auth(s.handleRecords))
	mux.HandleFunc("GET /api/ui/pivot", s.auth(s.handlePivot))
	mux.HandleFunc("GET /api/ui/snapshots", s.auth(s.handleSnapshots))
	mux.HandleFunc("GET /api/ui/search", s.auth(s.handleSearch))
	mux.HandleFunc("GET /api/ui/searches", s.auth(s.handleSearches))
	mux.HandleFunc("POST /api/ui/searches", s.analyst(s.handleSearchSave))
	mux.HandleFunc("POST /api/ui/searches/{id}/delete", s.analyst(s.handleSearchDelete))
	mux.HandleFunc("POST /api/ui/hunt", s.analyst(s.handleHunt))
	mux.HandleFunc("GET /api/ui/attacks", s.auth(s.handleAttacks))
	mux.HandleFunc("GET /api/ui/attacks/live", s.auth(s.handleAttacksLive))
	mux.HandleFunc("GET /api/ui/attacks/report", s.analyst(s.handleAttackReport))
	mux.HandleFunc("GET /api/ui/sources/stats", s.auth(s.handleSourcesStats))
	mux.HandleFunc("GET /api/ui/sources", s.adminOnly(s.handleSourcesConfig))
	mux.HandleFunc("POST /api/ui/sources", s.adminOnly(s.handleSourceSave))
	mux.HandleFunc("POST /api/ui/sources/{id}/{action}", s.adminOnly(s.handleSourceAction))
	mux.HandleFunc("POST /api/ui/shares", s.adminOnly(s.handleShareSave))
	mux.HandleFunc("POST /api/ui/shares/{id}/{action}", s.adminOnly(s.handleShareAction))
	mux.HandleFunc("GET /api/ui/sessions", s.auth(s.handleSessions))
	mux.HandleFunc("GET /api/ui/session", s.auth(s.handleSession))
	mux.HandleFunc("POST /api/ui/agents/{id}/snapshot", s.analyst(s.handleSnapshotRequest))
	mux.HandleFunc("GET /api/ui/agents/{id}", s.auth(s.handleAgent))
	mux.HandleFunc("POST /api/ui/agents/{id}/{action}", s.adminOnly(s.handleAgentAction))
	mux.HandleFunc("GET /api/ui/release/latest", s.adminOnly(s.handleLatestRelease))
	mux.HandleFunc("POST /api/ui/tokens", s.adminOnly(s.handleToken))
	mux.HandleFunc("GET /api/ui/canaries", s.auth(s.handleCanaries))
	mux.HandleFunc("POST /api/ui/canaries", s.adminOnly(s.handleCanaryCreate))
	mux.HandleFunc("POST /api/ui/canaries/{id}/delete", s.adminOnly(s.handleCanaryDelete))
	mux.HandleFunc("GET /api/ui/rules", s.auth(func(w http.ResponseWriter, r *http.Request, sess *session) {
		custom, errs := CustomInfo()
		writeJSON(w, map[string]any{"builtin": Catalog(), "custom": custom, "errors": errs, "suppressible": suppressibleList(),
			"sigma": sigmaStatus(), "malware": s.malwareStatus(), "forward": s.forwardStatus()})
	}))
	mux.HandleFunc("GET /api/ui/alerts/{id}/actions", s.auth(s.handleAlertActions))
	mux.HandleFunc("POST /api/ui/agents/{id}/respond", s.adminOnly(s.handleRespond))
	mux.HandleFunc("GET /api/ui/actions", s.auth(s.handleActions))
	mux.HandleFunc("POST /api/ui/actions/{id}/{decision}", s.adminOnly(s.handleActionDecision))
	mux.HandleFunc("GET /api/ui/intel", s.auth(func(w http.ResponseWriter, r *http.Request, sess *session) {
		writeJSON(w, map[string]any{"enabled": s.cfg.ThreatIntel, "lists": s.intel.status(), "vulns": s.vulnStatus(), "malware": s.malwareStatus()})
	}))
	mux.HandleFunc("GET /api/ui/incidents", s.auth(s.handleIncidents))
	mux.HandleFunc("GET /api/ui/incidents/{id}", s.auth(s.handleIncident))
	mux.HandleFunc("GET /api/ui/incidents/{id}/report", s.analyst(s.handleIncidentReport))
	mux.HandleFunc("POST /api/ui/incidents/{id}/{action}", s.analyst(s.handleIncidentAction))
	mux.HandleFunc("GET /api/ui/suppressions", s.auth(s.handleSuppressions))
	mux.HandleFunc("POST /api/ui/suppressions", s.analyst(s.handleSuppressionCreate))
	mux.HandleFunc("POST /api/ui/suppressions/{id}/{action}", s.analyst(s.handleSuppressionAction))
	mux.HandleFunc("GET /api/ui/chain", s.auth(s.handleChain))
	mux.HandleFunc("POST /api/ui/chain/verify", s.analyst(s.handleChainVerify))
	mux.HandleFunc("GET /api/ui/selftests", s.auth(func(w http.ResponseWriter, r *http.Request, sess *session) {
		agent := r.URL.Query().Get("agent")
		s.mu.Lock()
		out := []SelfTest{}
		for i := len(s.state.SelfTests) - 1; i >= 0 && len(out) < 20; i-- {
			if t := s.state.SelfTests[i]; agent == "" || t.Agent == agent {
				out = append(out, *t)
			}
		}
		s.mu.Unlock()
		writeJSON(w, out)
	}))
	mux.HandleFunc("GET /api/ui/notifiers", s.auth(func(w http.ResponseWriter, r *http.Request, sess *session) {
		writeJSON(w, map[string]any{"notifiers": s.notifierStatus(), "heartbeat": s.cfg.HeartbeatURL != "", "summary_time": s.cfg.SummaryTime})
	}))
	mux.HandleFunc("GET /api/ui/summary", s.adminOnly(func(w http.ResponseWriter, r *http.Request, sess *session) {
		writeJSON(w, map[string]any{"text": s.summaryText(time.Now()), "time": s.cfg.SummaryTime})
	}))
	mux.HandleFunc("POST /api/ui/summary/send", s.adminOnly(func(w http.ResponseWriter, r *http.Request, sess *session) {
		s.audit(sess.User, "admin.summary_send", map[string]any{})
		s.sendSummary(time.Now())
		writeJSON(w, map[string]any{"ok": true})
	}))
	mux.HandleFunc("POST /api/ui/notify/test", s.adminOnly(func(w http.ResponseWriter, r *http.Request, sess *session) {
		res := TestNotifiers(s.cfg, "", "vigil test notification from "+sess.User)
		failed := 0
		for _, n := range s.cfg.Notifiers {
			if err, ok := res[n.Name]; ok {
				if err != nil {
					failed++
				}
				s.noteDelivery(n, err)
			}
		}
		s.audit(sess.User, "admin.notify_test", map[string]any{"notifiers": len(res), "failed": failed})
		writeJSON(w, map[string]any{"notifiers": s.notifierStatus()})
	}))
	return secure(mux)
}

// versionedIndex rewrites the asset links in index.html to carry a hash of
// the embedded assets.
func versionedIndex(static fs.FS) ([]byte, string) {
	h := sha256.New()
	for _, name := range []string{"app.js", "theme.js", "style.css", "favicon.svg", "world.js"} {
		b, _ := fs.ReadFile(static, name)
		h.Write(b)
	}
	version := hex.EncodeToString(h.Sum(nil))[:12]
	index, _ := fs.ReadFile(static, "index.html")
	for _, name := range []string{"app.js", "theme.js", "style.css", "favicon.svg"} {
		index = bytes.ReplaceAll(index, []byte(`"`+name+`"`), []byte(`"`+name+"?v="+version+`"`))
	}
	return index, version
}

func decode(r *http.Request, w http.ResponseWriter, v any) bool {
	body, err := readBody(w, r)
	if err != nil || json.Unmarshal(body, v) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func lang(r *http.Request) string {
	if r.URL.Query().Get("lang") == "de" {
		return "de"
	}
	return "en"
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ User, Password, Code string }
	if !decode(r, w, &req) {
		return
	}
	ip := s.clientIP(r)
	tok, sess, err := s.login(clip(req.User, 64), req.Password, strings.TrimSpace(req.Code), ip)
	if err != nil {
		s.audit(clip(req.User, 64), "admin.login_failed", map[string]any{"ip": ip, "reason": err.Error()})
		status := http.StatusUnauthorized
		if err == errLimited {
			status = http.StatusTooManyRequests
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.audit(sess.User, "admin.login", map[string]any{"ip": ip})
	s.setCookie(w, tok, s.cfg.SessionHours*3600)
	writeJSON(w, s.meJSON(sess))
}

type agentView struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Hostname       string          `json:"hostname"`
	Version        string          `json:"version"`
	Status         string          `json:"status"`
	LastSeen       time.Time       `json:"last_seen"`
	LastIP         string          `json:"last_ip"`
	Enrolled       time.Time       `json:"enrolled"`
	OpenAlerts     int             `json:"open_alerts"`
	OpenBySev      map[string]int  `json:"open_by_severity"`
	Ports          int             `json:"ports"`
	Canaries       int             `json:"canaries"`
	CanaryRoots    []string        `json:"canary_roots"`
	CanaryReadable bool            `json:"canary_readable,omitempty"`
	ConfigSync     bool            `json:"config_sync"`
	Maintenance    *time.Time      `json:"maintenance_until,omitempty"`
	Updates        map[string]any  `json:"updates,omitempty"`
	Posture        map[string]any  `json:"posture,omitempty"`
	Contain        map[string]any  `json:"contain,omitempty"`
	ResponseTypes  []string        `json:"response_types"`
	Vulns          *VulnSummary    `json:"vulns,omitempty"`
	AppVulns       *AppVulnSummary `json:"app_vulns,omitempty"`
	Containers     []*Container    `json:"containers,omitempty"`
	DockerGroup    []string        `json:"docker_group,omitempty"`
	SelfTest       bool            `json:"selftest"`
	SelfUpdate     bool            `json:"self_update"`
	Update         *AgentUpdate    `json:"update,omitempty"`
}

func (s *Server) viewAgent(a *AgentRec) agentView {
	status := "online"
	switch {
	case a.LastSeen.IsZero():
		status = "pending"
	case a.Silent:
		status = "silent"
	case a.Stopped:
		status = "stopped"
	}
	v := agentView{ID: a.ID, Name: a.Name, Hostname: a.Hostname, Version: a.Version, Status: status,
		LastSeen: a.LastSeen, LastIP: a.LastIP, Enrolled: a.Enrolled, Ports: len(a.Ports),
		CanaryRoots: a.CanaryRoots, CanaryReadable: a.CanaryReadable, ConfigSync: a.AckedVersion >= a.ConfigVersion, OpenBySev: map[string]int{}, Updates: a.Updates, Posture: a.Posture, Contain: a.Contain, ResponseTypes: append([]string{}, a.ResponseTypes...), Vulns: a.Vulns, AppVulns: a.AppVulns, Containers: a.Containers, DockerGroup: a.DockerGroup, SelfTest: a.SelfTest, SelfUpdate: a.SelfUpdate, Update: a.Update}
	if time.Now().Before(a.MaintenanceUntil) {
		until := a.MaintenanceUntil
		v.Maintenance = &until
	}
	for _, al := range s.state.Alerts {
		if al.Agent == a.ID && al.Status == "open" {
			v.OpenAlerts++
			v.OpenBySev[al.Severity]++
		}
	}
	for _, c := range s.state.Canaries {
		if c.AgentID == a.ID {
			v.Canaries++
		}
	}
	return v
}

type alertView struct {
	*Alert
	Host         string `json:"host"`
	Suppressible bool   `json:"suppressible"`
	// ProcKey allows every port of the alert's program on its host.
	ProcKey string `json:"proc_key,omitempty"`
}

func (s *Server) viewAlert(al *Alert, lg string) alertView {
	cp := *al
	cp.Title = renderTitle(al.Rule, decodeParams(al.Detail), lg)
	v := alertView{Alert: &cp, Suppressible: Suppressible(al.Rule), ProcKey: alertProcKey(al)}
	if a := s.state.Agents[al.Agent]; a != nil {
		v.Host = a.Name
	}
	return v
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request, sess *session) {
	now := time.Now().UTC()
	hourStart := now.Truncate(time.Hour)
	var hours [24]int
	var sshFailed [24]int
	var window []Record
	s.store.Each(func(rec Record) {
		window = append(window, rec)
		age := hourStart.Sub(rec.Time.Truncate(time.Hour))
		idx := 23 - int(age/time.Hour)
		if idx < 0 || idx > 23 {
			return
		}
		hours[idx]++
		if rec.Event.Type == "ssh.failed" {
			sshFailed[idx] += int(num(rec.Event.Data, "count"))
		}
	})

	s.mu.Lock()
	defer s.mu.Unlock()
	agents := []agentView{}
	for _, a := range s.state.Agents {
		agents = append(agents, s.viewAgent(a))
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	bySev := map[string]int{}
	recent := []alertView{}
	for i := len(s.state.Alerts) - 1; i >= 0; i-- {
		al := s.state.Alerts[i]
		if al.Status == "open" {
			bySev[al.Severity]++
			if len(recent) < 8 {
				recent = append(recent, s.viewAlert(al, lang(r)))
			}
		}
	}
	activeSuppressions := 0
	for _, sp := range s.state.Suppressions {
		if sp.active(now) {
			activeSuppressions++
		}
	}
	canaries, triggered := 0, 0
	for _, c := range s.state.Canaries {
		canaries++
		if c.Triggers > 0 {
			triggered++
		}
	}
	seq, head := s.store.Head()
	out := s.dashboard(now, window)
	for k, v := range map[string]any{
		"agents": agents, "open_by_severity": bySev, "recent_alerts": recent,
		"events_per_hour": hours, "ssh_failed_per_hour": sshFailed,
		"hour_start": hourStart.Add(-23 * time.Hour),
		"canaries":   canaries, "canaries_triggered": triggered, "suppressions": activeSuppressions,
		"chain": map[string]any{"ok": s.store.ChainOK, "seq": seq, "head": head, "verified_at": s.store.VerifiedAt},
	} {
		out[k] = v
	}
	writeJSON(w, out)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	status, agent := q.Get("status"), q.Get("agent")
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []alertView{}
	for i := len(s.state.Alerts) - 1; i >= 0 && len(out) < 500; i-- {
		al := s.state.Alerts[i]
		if (status != "" && al.Status != status) || (agent != "" && al.Agent != agent) {
			continue
		}
		out = append(out, s.viewAlert(al, lang(r)))
	}
	writeJSON(w, out)
}

func (s *Server) handleAlertAction(w http.ResponseWriter, r *http.Request, sess *session) {
	id, action := r.PathValue("id"), r.PathValue("action")
	next := map[string]string{"ack": "acked", "resolve": "resolved", "reopen": "open"}[action]
	if next == "" {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	var hit *Alert
	for _, al := range s.state.Alerts {
		if al.ID == id {
			hit = al
		}
	}
	if hit == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	now := time.Now().UTC()
	hit.Status, hit.By, hit.Updated = next, sess.User, now
	if next != "open" && hit.Acked == nil {
		hit.Acked = &now
	}
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "alert."+action, map[string]any{"alert": id, "rule": hit.Rule})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleEventsList(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	before, _ := strconv.ParseUint(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	recs := s.store.Recent(Query{Agent: q.Get("agent"), Prefix: q.Get("type"), Before: before, Limit: limit})
	names := s.agentNames()
	role := s.roleFor(sess)
	out := make([]viewRecord, len(recs))
	for i, rec := range recs {
		out[i] = s.view(rec, names, role)
	}
	writeJSON(w, out)
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request, sess *session) {
	s.mu.Lock()
	a := s.state.Agents[r.PathValue("id")]
	if a == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	ports := []map[string]any{}
	for _, p := range a.Ports {
		cp := map[string]any{}
		for k, v := range p {
			cp[k] = v
		}
		cp["expected"] = portExpected(a, p)
		cp["proc_key"] = procKey(p)
		ports = append(ports, cp)
	}
	view := s.viewAgent(a)
	s.mu.Unlock()
	logins := s.store.Recent(Query{Agent: a.ID, Prefix: "ssh.login", Limit: 50})
	writeJSON(w, map[string]any{"agent": view, "ports": ports, "logins": logins})
}

func (s *Server) handleAgentAction(w http.ResponseWriter, r *http.Request, sess *session) {
	id, action := r.PathValue("id"), r.PathValue("action")
	var req struct {
		Name    string `json:"name"`
		Key     string `json:"key"`
		Minutes int    `json:"minutes"`
		Version string `json:"version"`
	}
	if !decode(r, w, &req) {
		return
	}
	s.mu.Lock()
	a := s.state.Agents[id]
	if a == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"agent": id}
	switch action {
	case "rename":
		name := clip(strings.TrimSpace(req.Name), 100)
		if name == "" {
			s.mu.Unlock()
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		data["old"], data["new"] = a.Name, name
		a.Name = name
	case "accept-port":
		if a.Baseline == nil {
			a.Baseline = map[string]bool{}
		}
		var accepted []map[string]any
		for _, p := range a.Ports {
			k := str(p, "key")
			switch {
			case req.Key == "*" || k == req.Key:
				a.Baseline[k] = true
				accepted = append(accepted, p)
			case strings.HasPrefix(req.Key, "proc:") && procKey(p) == req.Key:
				accepted = append(accepted, p)
			}
		}
		if strings.HasPrefix(req.Key, "proc:") {
			a.Baseline[clip(req.Key, 200)] = true
		}
		for _, al := range s.state.Alerts {
			if al.Agent != id || al.Status != "open" || !strings.HasPrefix(al.Rule, "port.") {
				continue
			}
			// a process key also covers ports of earlier runs that are
			// closed by now (a new random port on every start)
			hit := strings.HasPrefix(req.Key, "proc:") && alertProcKey(al) == req.Key
			k := decodeParams(al.Detail)["key"]
			for _, p := range accepted {
				hit = hit || str(p, "key") == k
			}
			if hit {
				now := time.Now().UTC()
				al.Status, al.By, al.Updated = "resolved", sess.User, now
				if al.Acked == nil {
					al.Acked = &now
				}
			}
		}
		data["key"] = req.Key
	case "maintenance":
		if req.Minutes < 0 || req.Minutes > 240 {
			s.mu.Unlock()
			http.Error(w, "minutes must be between 0 and 240", http.StatusBadRequest)
			return
		}
		a.MaintenanceUntil = time.Now().UTC().Add(time.Duration(req.Minutes) * time.Minute)
		data["minutes"] = req.Minutes
	case "selftest":
		t, err := s.startSelfTest(a, sess.User)
		if err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		data["selftest"] = t.ID
	case "update":
		if err := s.askUpdate(a, req.Version, sess.User); err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		data["version"], data["from"] = req.Version, a.Version
	case "forget-port":
		delete(a.Baseline, req.Key)
		data["key"] = req.Key
	case "delete":
		data["name"] = a.Name
		delete(s.state.Agents, id)
		for cid, c := range s.state.Canaries {
			if c.AgentID == id {
				delete(s.state.Canaries, cid)
			}
		}
	default:
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "agent."+action, data)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request, sess *session) {
	s.mu.Lock()
	tok, t := s.newEnrollTokenLocked(sess.User)
	s.mu.Unlock()
	s.audit(sess.User, "enroll.token_created", map[string]any{"expires": t.Expires})
	writeJSON(w, map[string]any{"token": tok, "expires": t.Expires})
}

func (s *Server) handleCanaries(w http.ResponseWriter, r *http.Request, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type cv struct {
		*CanaryRec
		Host string `json:"host"`
	}
	out := []cv{}
	for _, c := range s.state.Canaries {
		v := cv{CanaryRec: c}
		if a := s.state.Agents[c.AgentID]; a != nil {
			v.Host = a.Name
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	writeJSON(w, map[string]any{"canaries": out, "types": proto.CanaryTypes})
}

const maxCanariesPerAgent = 50

var canaryParams = []string{"domain", "comment", "email"}

func (s *Server) handleCanaryCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		AgentID  string            `json:"agent_id"`
		Type     string            `json:"type"`
		Path     string            `json:"path"`
		Params   map[string]string `json:"params"`
		Readable bool              `json:"readable"`
	}
	if !decode(r, w, &req) {
		return
	}
	bad := func(msg string) { http.Error(w, msg, http.StatusBadRequest) }
	if !slices.Contains(proto.CanaryTypes, req.Type) {
		bad("unknown type")
		return
	}
	if !filepath.IsAbs(req.Path) || filepath.Clean(req.Path) != req.Path || len(req.Path) > 300 {
		bad("path must be absolute and clean")
		return
	}
	params := map[string]string{}
	for k, v := range req.Params {
		if v = clip(strings.TrimSpace(v), 120); v != "" && slices.Contains(canaryParams, k) {
			params[k] = v
		}
	}

	s.mu.Lock()
	a := s.state.Agents[req.AgentID]
	if a == nil {
		s.mu.Unlock()
		bad("unknown agent")
		return
	}
	inside := false
	for _, root := range a.CanaryRoots {
		if strings.HasPrefix(req.Path, root+"/") {
			inside = true
		}
	}
	n := 0
	for _, c := range s.state.Canaries {
		if c.AgentID == a.ID {
			n++
			if c.Path == req.Path {
				s.mu.Unlock()
				bad("a canary already uses this path")
				return
			}
		}
	}
	if !inside {
		s.mu.Unlock()
		bad("path is outside the canary roots this agent allows")
		return
	}
	// An older agent would ignore the field and place a 0600 file that
	// looks active but no service account can open.
	if req.Readable && !a.CanaryReadable {
		s.mu.Unlock()
		bad("this agent cannot place readable canaries yet, update it first")
		return
	}
	if n >= maxCanariesPerAgent {
		s.mu.Unlock()
		bad("too many canaries on this agent")
		return
	}
	c := &CanaryRec{ID: newID(8), AgentID: a.ID, Type: req.Type, Path: req.Path, Params: params, Readable: req.Readable,
		Created: time.Now().UTC(), By: sess.User, Status: "pending"}
	s.state.Canaries[c.ID] = c
	a.ConfigVersion++
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "canary.create", map[string]any{"canary_id": c.ID, "agent": a.ID, "type": c.Type, "path": c.Path, "readable": c.Readable})
	writeJSON(w, c)
}

func (s *Server) handleCanaryDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	s.mu.Lock()
	c := s.state.Canaries[id]
	if c == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	delete(s.state.Canaries, id)
	if a := s.state.Agents[c.AgentID]; a != nil {
		a.ConfigVersion++
	}
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "canary.delete", map[string]any{"canary_id": id, "agent": c.AgentID, "path": c.Path})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleChain(w http.ResponseWriter, r *http.Request, sess *session) {
	seq, head := s.store.Head()
	writeJSON(w, map[string]any{"ok": s.store.ChainOK, "error": s.store.ChainError, "seq": seq, "head": head, "verified_at": s.store.VerifiedAt})
}

func (s *Server) handleChainVerify(w http.ResponseWriter, r *http.Request, sess *session) {
	ok, msg := s.store.Verify()
	s.audit(sess.User, "chain.verify", map[string]any{"ok": ok, "error": msg})
	if !ok {
		s.chainBroken(msg)
	}
	s.handleChain(w, r, sess)
}

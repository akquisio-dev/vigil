package server

import (
	"errors"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Roles, weakest first. Accounts from before roles existed are admins.
var roleRank = map[string]int{"viewer": 1, "analyst": 2, "admin": 3}

func roleOf(u *User) string {
	if roleRank[u.Role] == 0 {
		return "admin"
	}
	return u.Role
}

// userCache rereads users.json only when it changed, so every request can
// check that its user still exists and what it may do.
type userCache struct {
	mu    sync.Mutex
	mtime time.Time
	size  int64
	users map[string]*User
}

func (s *Server) user(name string) *User {
	c := &s.users
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(usersFile(s.cfg.DataDir))
	if err != nil {
		return nil
	}
	if c.users == nil || !fi.ModTime().Equal(c.mtime) || fi.Size() != c.size {
		users, err := LoadUsers(s.cfg.DataDir)
		if err != nil {
			return nil
		}
		c.users, c.mtime, c.size = users, fi.ModTime(), fi.Size()
	}
	return c.users[name]
}

// endSessions logs a user out everywhere, for example after removal or a
// password change.
func (s *Server) endSessions(name string, except *session) {
	s.smu.Lock()
	defer s.smu.Unlock()
	for k, sess := range s.sessions {
		if sess.User == name && sess != except {
			delete(s.sessions, k)
		}
	}
}

func (s *Server) newSession(name, ip string) (string, *session) {
	tok := newID(32)
	sess := &session{User: name, CSRF: newID(16), Expires: time.Now().Add(time.Duration(s.cfg.SessionHours) * time.Hour), IP: ip}
	s.smu.Lock()
	s.sessions[sha(tok)] = sess
	s.smu.Unlock()
	return tok, sess
}

// reauth checks the current TOTP code of the signed-in user before a
// sensitive change.
func (s *Server) reauth(name, code string) error {
	ok := false
	err := UpdateUsers(s.cfg.DataDir, func(users map[string]*User) error {
		if u := users[name]; u != nil {
			ok = checkTOTP(u, strings.TrimSpace(code), time.Now())
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("wrong or reused code")
	}
	return nil
}

var userName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

const minPassword = 12

// ---------- own account ----------

type passkeyView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used"`
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, sess *session) {
	u := s.user(sess.User)
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	keys := []passkeyView{}
	for _, p := range u.Passkeys {
		keys = append(keys, passkeyView{ID: p.ID, Name: p.Name, Created: p.Created, LastUsed: p.LastUsed})
	}
	writeJSON(w, map[string]any{"name": u.Name, "role": roleOf(u), "created": u.Created, "last_login": u.LastLogin,
		"passkeys": keys, "password_changed": u.PasswordChanged, "rp_id": s.relyingParty(r.Host).ID})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Current, Code, New string }
	if !decode(r, w, &req) {
		return
	}
	if len(req.New) < minPassword || len(req.New) > 200 {
		http.Error(w, "the new password needs at least 12 characters", http.StatusBadRequest)
		return
	}
	ip := s.clientIP(r)
	if s.limit.blocked("ip:"+ip, "user:"+sess.User) {
		http.Error(w, errLimited.Error(), http.StatusTooManyRequests)
		return
	}
	hash, err := HashPassword(req.New)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bad := false
	err = UpdateUsers(s.cfg.DataDir, func(users map[string]*User) error {
		u := users[sess.User]
		if u == nil || !checkPassword(u.PassHash, req.Current) || !checkTOTP(u, strings.TrimSpace(req.Code), time.Now()) {
			bad = true
			return nil
		}
		u.PassHash, u.PasswordChanged = hash, time.Now().UTC()
		return nil
	})
	if err == nil && bad {
		s.limit.fail("ip:"+ip, "user:"+sess.User)
		err = errors.New("wrong password or code")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	s.endSessions(sess.User, sess)
	s.audit(sess.User, "account.password_changed", map[string]any{"ip": ip})
	writeJSON(w, map[string]bool{"ok": true})
}

// ---------- passkeys ----------

func (s *Server) handlePasskeyBegin(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Code string }
	if !decode(r, w, &req) {
		return
	}
	if err := s.reauth(sess.User, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	u := s.user(sess.User)
	tok, ch := s.challenges.issue("reg:" + sess.User)
	if tok == "" || u == nil {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	exclude := []string{}
	for _, p := range u.Passkeys {
		exclude = append(exclude, p.ID)
	}
	party := s.relyingParty(r.Host)
	writeJSON(w, map[string]any{"token": tok, "challenge": ch, "rp_id": party.ID, "rp_name": "vigil",
		"user_id": b64u.EncodeToString([]byte(sha("vigil-user:" + u.Name))[:32]), "user_name": u.Name, "exclude": exclude})
}

func (s *Server) handlePasskeyFinish(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Token, Name                   string
		ClientData, AttestationObject string
	}
	if !decode(r, w, &req) {
		return
	}
	ch, ok := s.challenges.take(req.Token, "reg:"+sess.User)
	if !ok {
		http.Error(w, "challenge expired", http.StatusBadRequest)
		return
	}
	cd, err1 := b64u.DecodeString(req.ClientData)
	ao, err2 := b64u.DecodeString(req.AttestationObject)
	if err1 != nil || err2 != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pk, err := verifyRegistration(s.relyingParty(r.Host), ch, cd, ao)
	if err != nil {
		s.audit(sess.User, "account.passkey_rejected", map[string]any{"error": err.Error()})
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pk.Name = cleanParam(strings.TrimSpace(req.Name))
	if pk.Name == "" {
		pk.Name = "Passkey"
	}
	if len(pk.Name) > 60 {
		pk.Name = pk.Name[:60]
	}
	err = UpdateUsers(s.cfg.DataDir, func(users map[string]*User) error {
		for _, u := range users {
			for _, p := range u.Passkeys {
				if p.ID == pk.ID {
					return errors.New("this passkey is already registered")
				}
			}
		}
		u := users[sess.User]
		if u == nil {
			return errors.New("unknown user")
		}
		if len(u.Passkeys) >= 10 {
			return errors.New("at most 10 passkeys")
		}
		u.Passkeys = append(u.Passkeys, pk)
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.audit(sess.User, "account.passkey_added", map[string]any{"name": pk.Name, "id": pk.ID[:min(12, len(pk.ID))]})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Code string }
	if !decode(r, w, &req) {
		return
	}
	if err := s.reauth(sess.User, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	id, found := r.PathValue("id"), false
	UpdateUsers(s.cfg.DataDir, func(users map[string]*User) error {
		if u := users[sess.User]; u != nil {
			for i, p := range u.Passkeys {
				if p.ID == id {
					u.Passkeys = append(u.Passkeys[:i:i], u.Passkeys[i+1:]...)
					found = true
					break
				}
			}
		}
		return nil
	})
	if !found {
		http.NotFound(w, r)
		return
	}
	s.audit(sess.User, "account.passkey_removed", map[string]any{"id": id[:min(12, len(id))]})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.limit.blocked("ip:" + s.clientIP(r)) {
		http.Error(w, errLimited.Error(), http.StatusTooManyRequests)
		return
	}
	tok, ch := s.challenges.issue("")
	if tok == "" {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"token": tok, "challenge": ch, "rp_id": s.relyingParty(r.Host).ID})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token, ID                                string
		ClientData, AuthenticatorData, Signature string
	}
	if !decode(r, w, &req) {
		return
	}
	ip := s.clientIP(r)
	if s.limit.blocked("ip:" + ip) {
		http.Error(w, errLimited.Error(), http.StatusTooManyRequests)
		return
	}
	fail := func(name, reason string) {
		s.limit.fail("ip:" + ip)
		s.audit(name, "admin.login_failed", map[string]any{"ip": ip, "reason": "passkey: " + reason})
		http.Error(w, "passkey not accepted", http.StatusUnauthorized)
	}
	ch, ok := s.challenges.take(req.Token, "")
	if !ok {
		fail("", "challenge expired")
		return
	}
	cd, e1 := b64u.DecodeString(req.ClientData)
	ad, e2 := b64u.DecodeString(req.AuthenticatorData)
	sig, e3 := b64u.DecodeString(req.Signature)
	if e1 != nil || e2 != nil || e3 != nil {
		fail("", "bad encoding")
		return
	}
	party := s.relyingParty(r.Host)
	var name string
	var verr error
	err := UpdateUsers(s.cfg.DataDir, func(users map[string]*User) error {
		for _, u := range users {
			for _, p := range u.Passkeys {
				if p.ID != req.ID {
					continue
				}
				name = u.Name
				if verr = verifyAssertion(party, ch, p, cd, ad, sig); verr == nil {
					p.LastUsed = time.Now().UTC()
					u.LastLogin = p.LastUsed
				}
				return nil
			}
		}
		verr = errors.New("unknown passkey")
		return nil
	})
	if err == nil {
		err = verr
	}
	if err != nil {
		fail(name, err.Error())
		return
	}
	tok, sess := s.newSession(name, ip)
	s.audit(name, "admin.login", map[string]any{"ip": ip, "method": "passkey"})
	s.setCookie(w, tok, s.cfg.SessionHours*3600)
	writeJSON(w, s.meJSON(sess))
}

// ---------- user management (admins) ----------

type userView struct {
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Created   time.Time `json:"created"`
	LastLogin time.Time `json:"last_login"`
	Passkeys  int       `json:"passkeys"`
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, sess *session) {
	users, err := LoadUsers(s.cfg.DataDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := []userView{}
	for _, u := range users {
		out = append(out, userView{Name: u.Name, Role: roleOf(u), Created: u.Created, LastLogin: u.LastLogin, Passkeys: len(u.Passkeys)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, out)
}

// NewUser creates an account with a random password and TOTP secret.
func NewUser(name, role string) (*User, string, error) {
	if !userName.MatchString(name) {
		return nil, "", errors.New("names use a to z, 0 to 9, '.', '_' and '-', at most 32 characters")
	}
	if roleRank[role] == 0 {
		return nil, "", errors.New("role must be viewer, analyst or admin")
	}
	pw := newID(12)
	hash, err := HashPassword(pw)
	if err != nil {
		return nil, "", err
	}
	return &User{Name: name, Role: role, PassHash: hash, TOTPSecret: NewTOTPSecret(), Created: time.Now().UTC()}, pw, nil
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Name, Role, Code string }
	if !decode(r, w, &req) {
		return
	}
	if err := s.reauth(sess.User, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	u, pw, err := NewUser(strings.TrimSpace(req.Name), req.Role)
	if err == nil {
		err = UpdateUsers(s.cfg.DataDir, func(users map[string]*User) error {
			if users[u.Name] != nil {
				return errors.New("this user exists")
			}
			users[u.Name] = u
			return nil
		})
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	uri := TOTPURI(u.Name, u.TOTPSecret, "vigil")
	q, _ := QR(uri)
	rows := make([]string, len(q))
	for i, row := range q {
		var b strings.Builder
		for _, d := range row {
			if d {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		rows[i] = b.String()
	}
	s.audit(sess.User, "user.created", map[string]any{"user": u.Name, "role": u.Role})
	writeJSON(w, map[string]any{"name": u.Name, "password": pw, "totp_secret": u.TOTPSecret, "totp_uri": uri, "qr": rows})
}

func (s *Server) handleUserAction(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Role, Code string }
	if !decode(r, w, &req) {
		return
	}
	name, action := r.PathValue("name"), r.PathValue("action")
	if action != "role" && action != "delete" {
		http.NotFound(w, r)
		return
	}
	if err := s.reauth(sess.User, req.Code); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	err := UpdateUsers(s.cfg.DataDir, func(users map[string]*User) error {
		u := users[name]
		if u == nil {
			return errors.New("unknown user")
		}
		admins := 0
		for _, x := range users {
			if roleOf(x) == "admin" {
				admins++
			}
		}
		lastAdmin := roleOf(u) == "admin" && admins == 1
		switch action {
		case "delete":
			if name == sess.User {
				return errors.New("you cannot remove yourself")
			}
			if lastAdmin {
				return errors.New("the last admin cannot be removed")
			}
			delete(users, name)
		case "role":
			if roleRank[req.Role] == 0 {
				return errors.New("role must be viewer, analyst or admin")
			}
			if lastAdmin && req.Role != "admin" {
				return errors.New("the last admin must stay admin")
			}
			u.Role = req.Role
		}
		return nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.endSessions(name, nil)
	s.audit(sess.User, "user."+map[string]string{"delete": "removed", "role": "role_changed"}[action], map[string]any{"user": name, "role": req.Role})
	writeJSON(w, map[string]bool{"ok": true})
}

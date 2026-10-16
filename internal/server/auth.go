package server

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const pbkdf2Iter = 600_000

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func newID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func checkPassword(stored, pw string) bool {
	f := strings.Split(stored, "$")
	if len(f) != 4 || f[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 100_000 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(f[2])
	want, err2 := base64.RawStdEncoding.DecodeString(f[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash keeps the timing of unknown user names equal to wrong passwords.
var dummyHash, _ = HashPassword("vigil-timing-equalizer")

func NewTOTPSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func TOTPURI(user, secret, issuer string) string {
	return "otpauth://totp/" + url.PathEscape(issuer+":"+user) + "?secret=" + secret + "&issuer=" + url.QueryEscape(issuer) + "&algorithm=SHA1&digits=6&period=30"
}

func totpAt(secret []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

// checkTOTP accepts the current step and one step on either side, and never
// the same step twice.
func checkTOTP(u *User, code string, now time.Time) bool {
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(u.TOTPSecret))
	if err != nil || len(code) != 6 {
		return false
	}
	step := now.Unix() / 30
	for _, c := range []int64{step - 1, step, step + 1} {
		if c <= u.LastTOTP {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, c)), []byte(code)) == 1 {
			u.LastTOTP = c
			return true
		}
	}
	return false
}

type session struct {
	User    string
	CSRF    string
	Expires time.Time
	IP      string
}

type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

const (
	limitWindow = 15 * time.Minute
	limitFails  = 5
)

func (l *limiter) blocked(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		n := 0
		for _, t := range l.fails[k] {
			if now.Sub(t) < limitWindow {
				n++
			}
		}
		if n >= limitFails {
			return true
		}
	}
	return false
}

func (l *limiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		var keep []time.Time
		for _, t := range l.fails[k] {
			if now.Sub(t) < limitWindow {
				keep = append(keep, t)
			}
		}
		l.fails[k] = append(keep, now)
	}
}

func (l *limiter) reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.fails, k)
	}
}

const cookieName = "vigil_session"

var errLimited = errors.New("too many attempts, wait 15 minutes")

// login returns a new session token. Caller holds no lock.
func (s *Server) login(name, password, code, ip string) (string, *session, error) {
	if s.limit.blocked("ip:"+ip, "user:"+name) {
		return "", nil, errLimited
	}
	var u *User
	var ok bool
	err := UpdateUsers(s.cfg.DataDir, func(users map[string]*User) error {
		u = users[name]
		hash := dummyHash
		if u != nil {
			hash = u.PassHash
		}
		ok = checkPassword(hash, password) && u != nil && checkTOTP(u, code, time.Now())
		if ok {
			u.LastLogin = time.Now().UTC()
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if !ok {
		s.limit.fail("ip:"+ip, "user:"+name)
		return "", nil, errors.New("invalid credentials")
	}
	s.limit.reset("user:" + name)
	tok, sess := s.newSession(name, ip)
	return tok, sess, nil
}

func (s *Server) sessionFor(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	s.smu.Lock()
	defer s.smu.Unlock()
	sess := s.sessions[sha(c.Value)]
	if sess == nil {
		return nil
	}
	if time.Now().After(sess.Expires) {
		delete(s.sessions, sha(c.Value))
		return nil
	}
	return sess
}

func (s *Server) logout(r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.smu.Lock()
		delete(s.sessions, sha(c.Value))
		s.smu.Unlock()
	}
}

func (s *Server) setCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.cfg.cookieSecure(), SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

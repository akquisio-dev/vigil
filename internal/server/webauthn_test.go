package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"github.com/akquisio-dev/vigil/internal/proto"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cborEnc writes the few CBOR shapes a test authenticator needs.
func cborHead(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}

func cborInt(v int) []byte {
	if v >= 0 {
		return cborHead(0, v)
	}
	return cborHead(1, -1-v)
}

func cborBytes(b []byte) []byte { return append(cborHead(2, len(b)), b...) }
func cborText(s string) []byte  { return append(cborHead(3, len(s)), s...) }

type fakeAuthenticator struct {
	ec      *ecdsa.PrivateKey
	ed      ed25519.PrivateKey
	credID  []byte
	counter uint32
	flags   byte
}

func newFake(t *testing.T, ed bool) *fakeAuthenticator {
	f := &fakeAuthenticator{credID: []byte(newID(16)), flags: flagUP | flagUV}
	if ed {
		_, f.ed, _ = ed25519.GenerateKey(rand.Reader)
	} else {
		f.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return f
}

func (f *fakeAuthenticator) coseKey() []byte {
	var b []byte
	if f.ed != nil {
		b = append(cborHead(5, 4), cborInt(1)...)
		b = append(b, cborInt(1)...)
		b = append(b, cborInt(3)...)
		b = append(b, cborInt(coseEdDSA)...)
		b = append(b, cborInt(-1)...)
		b = append(b, cborInt(6)...)
		b = append(b, cborInt(-2)...)
		return append(b, cborBytes(f.ed.Public().(ed25519.PublicKey))...)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	f.ec.X.FillBytes(x)
	f.ec.Y.FillBytes(y)
	b = append(cborHead(5, 5), cborInt(1)...)
	b = append(b, cborInt(2)...)
	b = append(b, cborInt(3)...)
	b = append(b, cborInt(coseES256)...)
	b = append(b, cborInt(-1)...)
	b = append(b, cborInt(1)...)
	b = append(b, cborInt(-2)...)
	b = append(b, cborBytes(x)...)
	b = append(b, cborInt(-3)...)
	return append(b, cborBytes(y)...)
}

func (f *fakeAuthenticator) authData(rpID string, withCred bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte{}, h[:]...)
	flags := f.flags
	if withCred {
		flags |= flagAT
	}
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, f.counter)
	if withCred {
		b = append(b, make([]byte, 16)...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(f.credID)))
		b = append(b, f.credID...)
		b = append(b, f.coseKey()...)
	}
	return b
}

func clientJSON(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": challenge, "origin": origin})
	return b
}

func (f *fakeAuthenticator) create(rpID, challenge, origin string) (cd, att []byte) {
	cd = clientJSON("webauthn.create", challenge, origin)
	att = append(cborHead(5, 3), cborText("fmt")...)
	att = append(att, cborText("none")...)
	att = append(att, cborText("attStmt")...)
	att = append(att, cborHead(5, 0)...)
	att = append(att, cborText("authData")...)
	att = append(att, cborBytes(f.authData(rpID, true))...)
	return cd, att
}

func (f *fakeAuthenticator) get(rpID, challenge, origin string) (cd, ad, sig []byte) {
	cd = clientJSON("webauthn.get", challenge, origin)
	ad = f.authData(rpID, false)
	h := sha256.Sum256(cd)
	msg := append(append([]byte{}, ad...), h[:]...)
	if f.ed != nil {
		return cd, ad, ed25519.Sign(f.ed, msg)
	}
	d := sha256.Sum256(msg)
	sig, _ = ecdsa.SignASN1(rand.Reader, f.ec, d[:])
	return cd, ad, sig
}

func TestWebAuthn(t *testing.T) {
	party := rp{ID: "soc.example.com", Origin: "https://soc.example.com"}
	for _, ed := range []bool{false, true} {
		f := newFake(t, ed)
		cd, att := f.create(party.ID, "chal-1", party.Origin)
		pk, err := verifyRegistration(party, "chal-1", cd, att)
		if err != nil {
			t.Fatalf("ed=%v register: %v", ed, err)
		}
		if _, err := verifyRegistration(party, "chal-2", cd, att); err == nil {
			t.Fatal("registration with another challenge must fail")
		}
		if cd, att := f.create(party.ID, "c", "https://evil.example.com"); true {
			if _, err := verifyRegistration(party, "c", cd, att); err == nil {
				t.Fatal("foreign origin must fail")
			}
		}
		if cd, att := f.create("evil.example.com", "c", party.Origin); true {
			if _, err := verifyRegistration(party, "c", cd, att); err == nil {
				t.Fatal("foreign relying party must fail")
			}
		}

		f.counter = 5
		cd, ad, sig := f.get(party.ID, "login-1", party.Origin)
		if err := verifyAssertion(party, "login-1", pk, cd, ad, sig); err != nil {
			t.Fatalf("ed=%v login: %v", ed, err)
		}
		if err := verifyAssertion(party, "login-1", pk, cd, ad, sig); err == nil {
			t.Fatal("the same counter twice must fail")
		}
		f.counter = 6
		cd, ad, sig = f.get(party.ID, "login-2", party.Origin)
		bad := append([]byte{}, sig...)
		bad[len(bad)-1] ^= 1
		if err := verifyAssertion(party, "login-2", pk, cd, ad, bad); err == nil {
			t.Fatal("a broken signature must fail")
		}
		if err := verifyAssertion(party, "other", pk, cd, ad, sig); err == nil {
			t.Fatal("wrong challenge must fail")
		}
		f.flags = flagUP
		f.counter = 7
		cd, ad, sig = f.get(party.ID, "login-3", party.Origin)
		if err := verifyAssertion(party, "login-3", pk, cd, ad, sig); err == nil || !strings.Contains(err.Error(), "verified") {
			t.Fatalf("login without user verification must fail: %v", err)
		}
	}
}

func TestCBORRejectsGarbage(t *testing.T) {
	for _, b := range [][]byte{{}, {0x5f}, {0x5a, 0xff, 0xff, 0xff, 0xff}, {0xbf}, bytes.Repeat([]byte{0x81}, 20)} {
		if _, _, err := cborDecode(b); err == nil {
			t.Errorf("accepted %x", b)
		}
	}
}

func TestRolesAndPasskeyLogin(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{DataDir: dir, PublicURL: "https://soc.example.com", SessionHours: 1}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	viewer, _, _ := NewUser("vera", "viewer")
	admin, _, _ := NewUser("ada", "admin")
	f := newFake(t, false)
	cd, att := f.create("soc.example.com", "c0", "https://soc.example.com")
	pk, _ := verifyRegistration(rp{ID: "soc.example.com", Origin: "https://soc.example.com"}, "c0", cd, att)
	admin.Passkeys = []*Passkey{pk}
	if err := SaveUsers(dir, map[string]*User{"vera": viewer, "ada": admin}); err != nil {
		t.Fatal(err)
	}
	h := s.uiHandler()
	call := func(method, path, body, tok, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if tok != "" {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		}
		r.Header.Set("X-CSRF", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	vtok, vs := s.newSession("vera", "1.2.3.4")
	if w := call("GET", "/api/ui/overview", "", vtok, ""); w.Code != 200 {
		t.Fatalf("viewer may read: %d", w.Code)
	}
	if w := call("POST", "/api/ui/tokens", "{}", vtok, vs.CSRF); w.Code != http.StatusForbidden {
		t.Fatalf("viewer must not create enrollment tokens: %d", w.Code)
	}
	if w := call("POST", "/api/ui/suppressions", `{"rule":"file.cron","reason":"x"}`, vtok, vs.CSRF); w.Code != http.StatusForbidden {
		t.Fatalf("viewer must not suppress: %d", w.Code)
	}

	// passkey login end to end through the handlers
	w := call("POST", "/api/ui/passkey/begin", "{}", "", "")
	var begin struct{ Token, Challenge string }
	json.Unmarshal(w.Body.Bytes(), &begin)
	f.counter = 1
	gcd, gad, gsig := f.get("soc.example.com", begin.Challenge, "https://soc.example.com")
	body, _ := json.Marshal(map[string]string{"token": begin.Token, "id": pk.ID, "clientData": b64u.EncodeToString(gcd),
		"authenticatorData": b64u.EncodeToString(gad), "signature": b64u.EncodeToString(gsig)})
	w = call("POST", "/api/ui/passkey/finish", string(body), "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"role":"admin"`) {
		t.Fatalf("passkey login: %d %s", w.Code, w.Body.String())
	}
	if w := call("POST", "/api/ui/passkey/finish", string(body), "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("a used challenge must not log in again: %d", w.Code)
	}

	// removing the viewer ends the session at once
	UpdateUsers(dir, func(u map[string]*User) error { delete(u, "vera"); return nil })
	time.Sleep(10 * time.Millisecond)
	if w := call("GET", "/api/ui/overview", "", vtok, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("removed user still has access: %d", w.Code)
	}
}

func TestResponseActionsFlow(t *testing.T) {
	dir := t.TempDir()
	s, err := New(&Config{DataDir: dir, SessionHours: 1})
	if err != nil {
		t.Fatal(err)
	}
	admin, _, _ := NewUser("ada", "admin")
	analyst, _, _ := NewUser("ana", "analyst")
	SaveUsers(dir, map[string]*User{"ada": admin, "ana": analyst})
	s.state.Agents["a1"] = &AgentRec{ID: "a1", Name: "web", ResponseTypes: []string{"block_ip"}}
	h := s.uiHandler()
	call := func(tok, csrf, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/ui/agents/a1/respond", strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		r.Header.Set("X-CSRF", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	secret := func(u *User) []byte {
		b, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.TOTPSecret)
		return b
	}
	code := func(u *User) string { return totpAt(secret(u), time.Now().Unix()/30) }
	atok, as := s.newSession("ana", "1.2.3.4")
	if w := call(atok, as.CSRF, `{"type":"block_ip","params":{"ip":"203.0.113.9"},"code":"`+code(analyst)+`"}`); w.Code != http.StatusForbidden {
		t.Fatalf("analysts cannot start response actions: %d", w.Code)
	}
	tok, ss := s.newSession("ada", "1.2.3.4")
	if w := call(tok, ss.CSRF, `{"type":"block_ip","params":{"ip":"10.0.0.5"},"code":"`+code(admin)+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("private addresses are refused: %d", w.Code)
	}
	if w := call(tok, ss.CSRF, `{"type":"block_ip","params":{"ip":"203.0.113.9"},"code":"000000"}`); w.Code != http.StatusForbidden {
		t.Fatalf("a wrong code is refused: %d", w.Code)
	}
	w := call(tok, ss.CSRF, `{"type":"block_ip","params":{"ip":"203.0.113.9","minutes":"60"},"code":"`+code(admin)+`"}`)
	if w.Code != 200 {
		t.Fatalf("respond: %d %s", w.Code, w.Body.String())
	}
	raw, sig := s.agentConfig(s.state.Agents["a1"])
	if proto.Verify(s.key.Public().(ed25519.PublicKey), raw, sig) != nil {
		t.Fatal("config must be signed")
	}
	var cfg proto.AgentConfig
	json.Unmarshal(raw, &cfg)
	if len(cfg.Actions) != 1 || cfg.Actions[0].Params["ip"] != "203.0.113.9" || cfg.Version != 1 {
		t.Fatalf("config: %+v", cfg)
	}
	s.evaluate(s.state.Agents["a1"], &Record{Event: proto.Event{Type: "response.result", Data: map[string]any{"action_id": cfg.Actions[0].ID, "ok": true, "detail": "blocked"}}})
	if s.state.Actions[0].Status != "done" || len(s.pendingActions("a1")) != 0 {
		t.Fatalf("result: %+v", s.state.Actions[0])
	}
}

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// WebAuthn (passkeys) with the standard library only. vigil asks for no
// attestation, so registration needs nothing but the credential's public
// key; every login checks the relying party, origin, challenge, user
// presence and verification, the signature and the signature counter.

var b64u = base64.RawURLEncoding

// ---------- minimal CBOR (RFC 8949): what authenticator data uses ----------

type cborDec struct {
	b []byte
	p int
}

var errCBOR = errors.New("bad CBOR")

func (d *cborDec) head() (major byte, arg uint64, err error) {
	if d.p >= len(d.b) {
		return 0, 0, errCBOR
	}
	ib := d.b[d.p]
	d.p++
	major, info := ib>>5, ib&0x1f
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24, info == 25, info == 26, info == 27:
		n := 1 << (info - 24)
		if d.p+n > len(d.b) {
			return 0, 0, errCBOR
		}
		for i := 0; i < n; i++ {
			arg = arg<<8 | uint64(d.b[d.p+i])
		}
		d.p += n
		return major, arg, nil
	}
	return 0, 0, errCBOR // indefinite lengths are not used by authenticators
}

// value decodes one item into int64, []byte, string, []any, map[any]any, bool or nil.
func (d *cborDec) value(depth int) (any, error) {
	if depth > 8 {
		return nil, errCBOR
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > 1<<62 {
			return nil, errCBOR
		}
		return int64(arg), nil
	case 1:
		if arg > 1<<62 {
			return nil, errCBOR
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(len(d.b)-d.p) {
			return nil, errCBOR
		}
		v := d.b[d.p : d.p+int(arg)]
		d.p += int(arg)
		if major == 3 {
			return string(v), nil
		}
		return append([]byte(nil), v...), nil
	case 4:
		if arg > 1000 {
			return nil, errCBOR
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > 1000 {
			return nil, errCBOR
		}
		out := map[any]any{}
		for i := uint64(0); i < arg; i++ {
			k, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, ok := k.([]any); ok {
				return nil, errCBOR
			}
			if _, ok := k.(map[any]any); ok {
				return nil, errCBOR
			}
			if _, ok := k.([]byte); ok {
				return nil, errCBOR
			}
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 7:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23:
			return nil, nil
		}
	}
	return nil, errCBOR
}

func cborDecode(b []byte) (any, int, error) {
	d := &cborDec{b: b}
	v, err := d.value(0)
	return v, d.p, err
}

// ---------- keys ----------

const (
	coseES256 = -7
	coseEdDSA = -8
)

// parseCOSEKey returns the public key and its algorithm.
func parseCOSEKey(b []byte) (any, int64, error) {
	v, _, err := cborDecode(b)
	if err != nil {
		return nil, 0, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, 0, errors.New("key is not a map")
	}
	kty, _ := m[int64(1)].(int64)
	alg, _ := m[int64(3)].(int64)
	crv, _ := m[int64(-1)].(int64)
	x, _ := m[int64(-2)].([]byte)
	switch {
	case kty == 2 && alg == coseES256 && crv == 1:
		y, _ := m[int64(-3)].([]byte)
		if len(x) != 32 || len(y) != 32 {
			return nil, 0, errors.New("bad P-256 key")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, 0, errors.New("point not on curve")
		}
		return pub, alg, nil
	case kty == 1 && alg == coseEdDSA && crv == 6:
		if len(x) != ed25519.PublicKeySize {
			return nil, 0, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), alg, nil
	}
	return nil, 0, fmt.Errorf("unsupported key (kty %d, alg %d)", kty, alg)
}

func verifySig(pub any, msg, sig []byte) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, h[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(k, msg, sig)
	}
	return false
}

// ---------- ceremonies ----------

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

type authData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	credID    []byte
	pubKey    []byte
}

func parseAuthData(b []byte, withCred bool) (*authData, error) {
	if len(b) < 37 {
		return nil, errors.New("authenticator data too short")
	}
	a := &authData{rpIDHash: b[:32], flags: b[32], signCount: binary.BigEndian.Uint32(b[33:37])}
	if !withCred {
		return a, nil
	}
	if a.flags&flagAT == 0 || len(b) < 37+16+2 {
		return nil, errors.New("no attested credential")
	}
	n := int(binary.BigEndian.Uint16(b[53:55]))
	if n == 0 || n > 1023 || len(b) < 55+n {
		return nil, errors.New("bad credential id")
	}
	a.credID = b[55 : 55+n]
	_, used, err := cborDecode(b[55+n:])
	if err != nil {
		return nil, err
	}
	a.pubKey = b[55+n : 55+n+used]
	return a, nil
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// rp is the relying party: the dashboard's host and origin.
type rp struct {
	ID     string
	Origin string
}

func (s *Server) relyingParty(host string) rp {
	if u, err := url.Parse(s.cfg.PublicURL); err == nil && u.Host != "" {
		return rp{ID: u.Hostname(), Origin: u.Scheme + "://" + u.Host}
	}
	scheme := "https"
	if !s.cfg.cookieSecure() {
		scheme = "http"
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return rp{ID: strings.Trim(h, "[]"), Origin: scheme + "://" + host}
}

func checkClientData(raw []byte, typ, challenge string, party rp) error {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return errors.New("bad client data")
	}
	switch {
	case cd.Type != typ:
		return errors.New("wrong ceremony type")
	case cd.Challenge != challenge:
		return errors.New("wrong challenge")
	case cd.Origin != party.Origin:
		return fmt.Errorf("wrong origin %q", cd.Origin)
	}
	return nil
}

func checkRP(a *authData, party rp) error {
	want := sha256.Sum256([]byte(party.ID))
	switch {
	case !bytes.Equal(a.rpIDHash, want[:]):
		return errors.New("wrong relying party")
	case a.flags&flagUP == 0:
		return errors.New("user not present")
	case a.flags&flagUV == 0:
		return errors.New("user not verified (PIN or biometrics required)")
	}
	return nil
}

// Passkey is a registered credential.
type Passkey struct {
	ID        string    `json:"id"` // base64url credential id
	PublicKey string    `json:"public_key"`
	Alg       int64     `json:"alg"`
	SignCount uint32    `json:"sign_count"`
	Name      string    `json:"name"`
	Created   time.Time `json:"created"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

// verifyRegistration checks a navigator.credentials.create() result.
func verifyRegistration(party rp, challenge string, clientDataJSON, attestationObject []byte) (*Passkey, error) {
	if err := checkClientData(clientDataJSON, "webauthn.create", challenge, party); err != nil {
		return nil, err
	}
	v, _, err := cborDecode(attestationObject)
	if err != nil {
		return nil, err
	}
	att, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("bad attestation object")
	}
	raw, _ := att["authData"].([]byte)
	a, err := parseAuthData(raw, true)
	if err != nil {
		return nil, err
	}
	if err := checkRP(a, party); err != nil {
		return nil, err
	}
	_, alg, err := parseCOSEKey(a.pubKey)
	if err != nil {
		return nil, err
	}
	return &Passkey{ID: b64u.EncodeToString(a.credID), PublicKey: b64u.EncodeToString(a.pubKey), Alg: alg,
		SignCount: a.signCount, Created: time.Now().UTC()}, nil
}

// verifyAssertion checks a navigator.credentials.get() result against a
// stored passkey and moves its signature counter forward.
func verifyAssertion(party rp, challenge string, pk *Passkey, clientDataJSON, authenticatorData, signature []byte) error {
	if err := checkClientData(clientDataJSON, "webauthn.get", challenge, party); err != nil {
		return err
	}
	a, err := parseAuthData(authenticatorData, false)
	if err != nil {
		return err
	}
	if err := checkRP(a, party); err != nil {
		return err
	}
	keyBytes, err := b64u.DecodeString(pk.PublicKey)
	if err != nil {
		return err
	}
	pub, _, err := parseCOSEKey(keyBytes)
	if err != nil {
		return err
	}
	cdHash := sha256.Sum256(clientDataJSON)
	if !verifySig(pub, append(append([]byte(nil), authenticatorData...), cdHash[:]...), signature) {
		return errors.New("bad signature")
	}
	// Counters that do not grow point to a cloned authenticator. Synced
	// passkeys always report 0, which is allowed.
	if a.signCount != 0 || pk.SignCount != 0 {
		if a.signCount <= pk.SignCount {
			return errors.New("signature counter went backwards")
		}
	}
	pk.SignCount = a.signCount
	return nil
}

// challenges are single use and expire after two minutes.
type challenges struct {
	mu sync.Mutex
	m  map[string]challengeRec
}

type challengeRec struct {
	value   string
	user    string // empty for login
	expires time.Time
}

func (c *challenges) issue(user string) (token, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]challengeRec{}
	}
	now := time.Now()
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	if len(c.m) > 1000 {
		return "", ""
	}
	token = newID(16)
	value = b64u.EncodeToString([]byte(newID(32)))
	c.m[token] = challengeRec{value: value, user: user, expires: now.Add(2 * time.Minute)}
	return token, value
}

func (c *challenges) take(token, user string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.m[token]
	delete(c.m, token)
	if !ok || time.Now().After(rec.expires) || rec.user != user {
		return "", false
	}
	return rec.value, true
}

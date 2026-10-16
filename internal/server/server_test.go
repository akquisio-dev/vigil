package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestChainDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		st.Append(&Record{Source: "agent", Event: proto.NewEvent("test.event", map[string]any{"i": i})})
	}
	if ok, msg := st.Verify(); !ok {
		t.Fatalf("fresh chain broken: %s", msg)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	raw, _ := os.ReadFile(files[0])
	os.WriteFile(files[0], []byte(strings.Replace(string(raw), `"i":2`, `"i":7`, 1)), 0o600)
	if ok, _ := st.Verify(); ok {
		t.Fatal("edited record not detected")
	}

	os.WriteFile(files[0], raw, 0o600)
	lines := strings.SplitAfter(string(raw), "\n")
	os.WriteFile(files[0], []byte(strings.Join(append(lines[:1], lines[2:]...), "")), 0o600)
	if ok, _ := (&Store{dir: dir, max: 10}).verifyFresh(); ok {
		t.Fatal("deleted record not detected")
	}
}

func (s *Store) verifyFresh() (bool, string) {
	s.verifyAndLoad()
	return s.ChainOK, s.ChainError
}

func TestPasswordAndTOTP(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !checkPassword(h, "correct horse battery") || checkPassword(h, "wrong") {
		t.Fatal("password check")
	}
	u := &User{TOTPSecret: NewTOTPSecret()}
	now := time.Now()
	secret := decodeSecret(t, u.TOTPSecret)
	code := totpAt(secret, now.Unix()/30)
	if !checkTOTP(u, code, now) {
		t.Fatal("valid code refused")
	}
	if checkTOTP(u, code, now) {
		t.Fatal("code accepted twice")
	}
	if checkTOTP(u, totpAt(secret, now.Unix()/30+5), now) {
		t.Fatal("code from the future accepted")
	}
}

func TestRenderTitle(t *testing.T) {
	got := renderTitle("file.cron", map[string]string{"path": "/etc/cron.d/x", "change": "added"}, "de")
	if got != "/etc/cron.d/x: neu angelegt" {
		t.Fatalf("got %q", got)
	}
	got = renderTitle("port.public", map[string]string{"proto": "tcp", "port": "80", "addr": "0.0.0.0"}, "en")
	if got != "New port tcp/80 on 0.0.0.0" {
		t.Fatalf("got %q", got)
	}
}

func TestRulesHaveBothLanguages(t *testing.T) {
	for id, r := range rules {
		if r.En == "" || r.De == "" || severityRank[r.Severity] == 0 && r.Severity != "info" {
			t.Errorf("rule %s incomplete", id)
		}
	}
}

func decodeSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32NoPad.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

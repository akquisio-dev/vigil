package server

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/backup"
	"github.com/akquisio-dev/vigil/internal/proto"
)

// backupFixture is a data directory with a pruned event log (so ANCHOR is
// in play), state, accounts, a cache that must stay out, and a config.
func backupFixture(t *testing.T) (*Config, string) {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	st, err := OpenStore(filepath.Join(data, "events"), 10)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		st.Append(&Record{Source: "agent", Event: proto.NewEvent("test.event", map[string]any{"i": i})})
	}
	st.file.Close()
	st.file = nil
	today := filepath.Join(data, "events", time.Now().UTC().Format("2006-01-02")+".jsonl")
	os.Rename(today, filepath.Join(data, "events", "2000-01-01.jsonl"))
	st.day = ""
	for i := 5; i < 9; i++ {
		st.Append(&Record{Source: "agent", Event: proto.NewEvent("test.event", map[string]any{"i": i})})
	}
	if err := st.Prune(30); err != nil {
		t.Fatal(err)
	}
	if ok, msg := st.Verify(); !ok {
		t.Fatal(msg)
	}
	if _, err := os.Stat(filepath.Join(data, "events", "ANCHOR")); err != nil {
		t.Fatal("fixture needs a pruned log")
	}
	state := &State{Agents: map[string]*AgentRec{"a1": {ID: "a1", Name: "web"}}}
	if err := state.Save(data); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(data, "server.key"), bytes.Repeat([]byte{7}, 32), 0o600)
	os.WriteFile(filepath.Join(data, "users.json"), []byte(`{"claude":{"name":"claude"}}`), 0o600)
	os.MkdirAll(filepath.Join(data, "intel"), 0o700)
	os.WriteFile(filepath.Join(data, "intel", "hashes.bin"), []byte("cache"), 0o600)
	os.MkdirAll(filepath.Join(data, "vuln"), 0o700)
	os.WriteFile(filepath.Join(data, "vuln", "kev.json"), []byte("cache"), 0o600)
	os.WriteFile(filepath.Join(data, "vuln", "packages-a1.json"), []byte(`{}`), 0o600)

	cfgDir := filepath.Join(root, "etc")
	os.MkdirAll(filepath.Join(cfgDir, "yara"), 0o700)
	os.WriteFile(filepath.Join(cfgDir, "yara", "linux.yar"), []byte("rule x { condition: false }"), 0o600)
	cfg := &Config{DataDir: data, YaraDir: filepath.Join(cfgDir, "yara")}
	cfgPath := filepath.Join(cfgDir, "server.json")
	os.WriteFile(cfgPath, []byte(`{"data_dir":"`+data+`"}`), 0o600)
	return cfg, cfgPath
}

func newKeys(t *testing.T) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	sec, pub, err := backup.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	k, _ := backup.ParseSecret(sec)
	p, _ := backup.ParsePublic(pub)
	return k, p
}

func TestBackupRoundTrip(t *testing.T) {
	cfg, cfgPath := backupFixture(t)
	key, pub := newKeys(t)

	// A line the server is writing right now stays out of the backup.
	today := filepath.Join(cfg.DataDir, "events", time.Now().UTC().Format("2006-01-02")+".jsonl")
	f, _ := os.OpenFile(today, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"hash":"half`)
	f.Close()

	var buf bytes.Buffer
	m, err := WriteBackup(cfg, BackupOptions{ConfigPath: cfgPath, Recipient: pub}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if m.ChainSeq != 9 {
		t.Fatalf("chain seq %d, want 9", m.ChainSeq)
	}
	names := map[string]bool{}
	for _, f := range m.Files {
		names[f.Path] = true
	}
	for _, want := range []string{"data/server.key", "data/state.json", "data/users.json", "data/events/ANCHOR", "data/vuln/packages-a1.json"} {
		if !names[want] {
			t.Errorf("%s missing from the backup", want)
		}
	}
	for n := range names {
		if strings.Contains(n, "intel/") || strings.HasSuffix(n, "kev.json") {
			t.Errorf("cache %s in the backup", n)
		}
	}
	if !names["config"+filepath.ToSlash(cfgPath)] || !names["config"+filepath.ToSlash(filepath.Join(cfg.YaraDir, "linux.yar"))] {
		t.Errorf("config files missing: %v", names)
	}
	if bytes.Contains(buf.Bytes(), []byte("test.event")) {
		t.Fatal("sealed backup contains plain text")
	}
	if _, err := CheckBackup(bytes.NewReader(buf.Bytes()), key); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(bytes.NewReader(buf.Bytes()), nil); err == nil {
		t.Fatal("sealed backup checked without a key")
	}

	// Restore over the old directory: the old one is moved aside, the new
	// one opens with an intact chain, the half line is gone.
	out := t.TempDir()
	res, err := RestoreBackup(bytes.NewReader(buf.Bytes()), key, RestoreOptions{DataDir: cfg.DataDir, ConfigOut: out})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(res.OldData, "users.json")); err != nil {
		t.Fatal("old data directory not kept")
	}
	st, err := OpenStore(filepath.Join(cfg.DataDir, "events"), 10)
	if err != nil || !st.ChainOK {
		t.Fatalf("restored chain: %v %s", err, st.ChainError)
	}
	if seq, _ := st.Head(); seq != 9 {
		t.Fatalf("restored seq %d", seq)
	}
	s, err := LoadState(cfg.DataDir)
	if err != nil || s.Agents["a1"] == nil {
		t.Fatal("state not restored")
	}
	if raw, _ := os.ReadFile(filepath.Join(cfg.DataDir, "server.key")); len(raw) != 32 {
		t.Fatal("server key not restored")
	}
	if len(res.Config) != 2 {
		t.Fatalf("config files: %v", res.Config)
	}
	if raw, _ := os.ReadFile(filepath.Join(out, cfgPath)); !strings.Contains(string(raw), "data_dir") {
		t.Fatal("config not written below -config-out")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "intel")); err == nil {
		t.Fatal("cache restored")
	}
}

func TestBackupDamageIsRefused(t *testing.T) {
	cfg, _ := backupFixture(t)
	key, pub := newKeys(t)
	var sealed, plain bytes.Buffer
	if _, err := WriteBackup(cfg, BackupOptions{Recipient: pub}, &sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBackup(cfg, BackupOptions{}, &plain); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(bytes.NewReader(plain.Bytes()), nil); err != nil {
		t.Fatalf("plain backup: %v", err)
	}
	for _, b := range [][]byte{sealed.Bytes(), plain.Bytes()} {
		for _, cut := range []int{len(b) / 3, len(b) - 9, len(b) - 1} {
			if _, err := CheckBackup(bytes.NewReader(b[:cut]), key); err == nil {
				t.Errorf("backup cut at %d/%d accepted", cut, len(b))
			}
		}
	}
	flip := bytes.Clone(sealed.Bytes())
	flip[len(flip)/2] ^= 1
	if _, err := CheckBackup(bytes.NewReader(flip), key); err == nil {
		t.Error("altered backup accepted")
	}
	other, _ := newKeys(t)
	if _, err := CheckBackup(bytes.NewReader(sealed.Bytes()), other); err == nil {
		t.Error("backup opened with another key")
	}

	// A refused restore leaves the data directory as it was.
	before, _ := os.ReadFile(filepath.Join(cfg.DataDir, "state.json"))
	if _, err := RestoreBackup(bytes.NewReader(flip), key, RestoreOptions{DataDir: cfg.DataDir}); err == nil {
		t.Fatal("restore of an altered backup")
	}
	after, _ := os.ReadFile(filepath.Join(cfg.DataDir, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("refused restore changed the data directory")
	}
	if left, _ := filepath.Glob(cfg.DataDir + ".*"); len(left) != 0 {
		t.Fatalf("refused restore left %v", left)
	}
}

func TestBackupEditedEventIsRefused(t *testing.T) {
	cfg, _ := backupFixture(t)
	files, _ := filepath.Glob(filepath.Join(cfg.DataDir, "events", "*.jsonl"))
	raw, _ := os.ReadFile(files[0])
	os.WriteFile(files[0], []byte(strings.Replace(string(raw), `"i":6`, `"i":1`, 1)), 0o600)
	var buf bytes.Buffer
	if _, err := WriteBackup(cfg, BackupOptions{}, &buf); err == nil || !strings.Contains(err.Error(), "event chain") {
		t.Fatalf("backup of a broken chain: %v", err)
	}
}

func TestRestoreRefusesRunningServer(t *testing.T) {
	cfg, _ := backupFixture(t)
	var buf bytes.Buffer
	if _, err := WriteBackup(cfg, BackupOptions{}, &buf); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = RestoreBackup(bytes.NewReader(buf.Bytes()), nil, RestoreOptions{DataDir: cfg.DataDir})
	unlock()
	if err == nil || !strings.Contains(err.Error(), "running vigil-server") {
		t.Fatalf("restore under a running server: %v", err)
	}
	// Into an empty place, e.g. a new machine.
	fresh := filepath.Join(t.TempDir(), "vigil")
	res, err := RestoreBackup(bytes.NewReader(buf.Bytes()), nil, RestoreOptions{DataDir: fresh})
	if err != nil || res.OldData != "" {
		t.Fatalf("restore to a new machine: %v %+v", err, res)
	}
}

func TestRestoreRefusesNewerVersion(t *testing.T) {
	cfg, _ := backupFixture(t)
	old := Version
	defer func() { Version = old }()
	Version = "v9.0.0"
	var buf bytes.Buffer
	if _, err := WriteBackup(cfg, BackupOptions{}, &buf); err != nil {
		t.Fatal(err)
	}
	Version = "v1.2.3"
	dst := filepath.Join(t.TempDir(), "d")
	if _, err := RestoreBackup(bytes.NewReader(buf.Bytes()), nil, RestoreOptions{DataDir: dst}); err == nil {
		t.Fatal("backup of a newer vigil restored")
	}
	if _, err := RestoreBackup(bytes.NewReader(buf.Bytes()), nil, RestoreOptions{DataDir: dst, Force: true}); err != nil {
		t.Fatal(err)
	}
}

func TestBackupDirKeepsNewest(t *testing.T) {
	cfg, _ := backupFixture(t)
	_, pub := newKeys(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600)
	for i := 0; i < 4; i++ {
		os.WriteFile(filepath.Join(dir, backupName(time.Now().Add(time.Duration(-10+i)*time.Hour))), []byte("x"), 0o600)
	}
	path, _, err := BackupToDir(cfg, BackupOptions{Recipient: pub}, dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	names, _ := listBackups(dir)
	if len(names) != 3 || filepath.Join(dir, names[2]) != path {
		t.Fatalf("kept %v, newest %s", names, path)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal("pruning removed a foreign file")
	}
}

func TestBackupStaleAlert(t *testing.T) {
	dir := t.TempDir()
	s := &Server{cfg: &Config{Backup: &BackupConfig{Dir: dir, MaxAgeHours: 36}}, state: &State{}, started: time.Now()}
	now := time.Now()
	if a := s.checkBackupAge(now); len(a) != 0 {
		t.Fatal("alert right after start")
	}
	if a := s.checkBackupAge(now.Add(37 * time.Hour)); len(a) != 1 || a[0].Rule != "server.backup_stale" {
		t.Fatalf("no alert without backups: %v", a)
	}
	p := filepath.Join(dir, backupName(now))
	os.WriteFile(p, []byte("x"), 0o600)
	os.Chtimes(p, now.Add(36*time.Hour), now.Add(36*time.Hour))
	s.checkBackupAge(now.Add(37 * time.Hour))
	if s.state.Alerts[0].Status != "resolved" {
		t.Fatal("fresh backup did not resolve the alert")
	}
}

func TestBackupEntryNames(t *testing.T) {
	for _, n := range []string{"data/../x", "/etc/passwd", "config/../../x", "data/a/../../b", "x/y", "data/", "config/a/../../../etc"} {
		if validEntry(n) {
			t.Errorf("%q accepted", n)
		}
	}
	for _, n := range []string{"data/state.json", "data/events/2026-01-01.jsonl", "config/etc/vigil/server.json", "MANIFEST.json"} {
		if !validEntry(n) {
			t.Errorf("%q refused", n)
		}
	}
	if !newerVersion("v0.20.0", "v0.19.2") || newerVersion("v0.19.2", "v0.19.2") || newerVersion("dev", "v0.1.0") {
		t.Error("version order")
	}
}

// After a restore the agent may hold a config version the restored server
// never reached; the next config must still be taken.
func TestRestoredServerResyncsAgentConfig(t *testing.T) {
	s, err := New(&Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ta := newTestAgent(t, s)
	ta.a.ConfigVersion = 3
	ta.seq++
	body, _ := json.Marshal(proto.Batch{AgentID: ta.a.ID, Seq: ta.seq, SentAt: time.Now(), ConfigVersion: 7, Events: []proto.Event{}})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/events", bytes.NewReader(body))
	req.Header.Set(proto.SigHeader, proto.Sign(ta.key, body))
	w := httptest.NewRecorder()
	s.handleEvents(w, req)
	var br proto.BatchResponse
	json.Unmarshal(w.Body.Bytes(), &br)
	if w.Code != 200 || br.ConfigVersion != 8 || len(br.Config) == 0 {
		t.Fatalf("agent ahead of the server got no new config: %d %+v", w.Code, br)
	}
}

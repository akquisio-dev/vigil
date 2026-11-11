package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func appendN(t *testing.T, st *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.Append(&Record{Source: "agent", Event: proto.NewEvent("test.event", map[string]any{"i": i})}); err != nil {
			t.Fatal(err)
		}
	}
}

func todayFile(dir string) string {
	return filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
}

// A server killed in the middle of a write leaves a cut line. The next
// server must append after the last whole record, on a line of its own,
// and the log must stay a single chain however often that happens.
func TestCutWriteDoesNotForkTheLog(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenStore(dir, 100)
	appendN(t, st, 3)
	st.file.Close()
	for crash := 0; crash < 3; crash++ {
		f, _ := os.OpenFile(todayFile(dir), os.O_WRONLY|os.O_APPEND, 0o600)
		f.WriteString(`{"hash":"cut off`)
		f.Close()
		st, _ = OpenStore(dir, 100)
		if !st.ChainOK || st.ChainWarning == "" {
			t.Fatalf("crash %d: ok=%v %q warning=%q", crash, st.ChainOK, st.ChainError, st.ChainWarning)
		}
		appendN(t, st, 2)
		st.file.Close()
	}
	st, _ = OpenStore(dir, 100)
	if !st.ChainOK {
		t.Fatalf("chain after three crashes: %s", st.ChainError)
	}
	if seq, _ := st.Head(); seq != 9 {
		t.Fatalf("seq %d, want 9 (no record numbered twice)", seq)
	}
	if !strings.Contains(st.ChainWarning, "3 unreadable lines") {
		t.Fatalf("warning %q", st.ChainWarning)
	}
	raw, _ := os.ReadFile(todayFile(dir))
	if n := bytes.Count(raw, []byte("\n")); n != 12 {
		t.Fatalf("%d lines, want 12 (9 records, 3 cut lines on their own)", n)
	}
}

// Before the fix the next server appended right onto the cut line. The
// whole record behind the cut part is read and checked like any other.
func TestRecordAfterCutPartOnSameLine(t *testing.T) {
	dir := t.TempDir()
	st, _ := OpenStore(dir, 100)
	appendN(t, st, 4)
	st.file.Close()
	raw, _ := os.ReadFile(todayFile(dir))
	lines := strings.SplitAfter(string(raw), "\n")
	// line 3 = cut part of some record + the whole line 3
	lines[2] = `{"hash":"0123","prev":"45","rec":{"seq":3,"ti` + lines[2]
	os.WriteFile(todayFile(dir), []byte(strings.Join(lines, "")), 0o600)
	st, _ = OpenStore(dir, 100)
	if !st.ChainOK || st.ChainWarning == "" {
		t.Fatalf("ok=%v %q warning=%q", st.ChainOK, st.ChainError, st.ChainWarning)
	}
	if seq, _ := st.Head(); seq != 4 {
		t.Fatalf("seq %d", seq)
	}

	// A cut line that hides a lost record is still a break.
	lines[2] = `{"hash":"0123","prev":"45","rec":{"seq":3,"ti` + "\n"
	os.WriteFile(todayFile(dir), []byte(strings.Join(lines, "")), 0o600)
	if ok, _ := (&Store{dir: dir, max: 10}).verifyFresh(); ok {
		t.Fatal("record lost behind a cut line not detected")
	}
}

func forkedStore(t *testing.T) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	st, _ := OpenStore(dir, 100)
	appendN(t, st, 5)
	st.file.Close()
	raw, _ := os.ReadFile(todayFile(dir))
	lines := strings.SplitAfter(string(raw), "\n")
	// A second record chained to line 2, as a restarted server with a stale
	// head wrote it.
	var cl chainLine
	json.Unmarshal([]byte(lines[1]), &cl)
	rec := []byte(`{"seq":3,"time":"2026-11-10T07:06:25Z","source":"server","event":{"type":"server.started","ts":"2026-11-10T07:06:25Z"}}`)
	fork, _ := json.Marshal(chainLine{Prev: cl.Hash, Hash: chainHash(cl.Hash, rec), Rec: rec})
	lines = append(lines[:3], append([]string{string(fork) + "\n"}, lines[3:]...)...)
	os.WriteFile(todayFile(dir), []byte(strings.Join(lines, "")), 0o600)
	return dir, lines
}

func TestAcceptBreaksIsPinnedToTheLines(t *testing.T) {
	dir, lines := forkedStore(t)
	st, _ := OpenStore(dir, 100)
	if st.ChainOK {
		t.Fatal("fork not detected")
	}
	if _, err := st.AcceptBreaks("test", "fork from a restart loop"); err != nil {
		t.Fatal(err)
	}
	st.file.Close()
	st, _ = OpenStore(dir, 100)
	if !st.ChainOK || st.Accepted != 2 {
		t.Fatalf("after accept: ok=%v %q accepted=%d", st.ChainOK, st.ChainError, st.Accepted)
	}
	got := st.Recent(Query{Prefix: "chain.accepted"})
	if len(got) != 1 || got[0].Source != "admin" || got[0].Event.Data["reason"] != "fork from a restart loop" {
		t.Fatalf("chain.accepted record: %+v", got)
	}
	n, err := st.AcceptBreaks("test", "again")
	if err != nil || n != 0 {
		t.Fatalf("second accept: %d %v", n, err)
	}
	st.file.Close()
	raw, _ := os.ReadFile(todayFile(dir))

	// Editing an accepted line breaks the chain again.
	edited := strings.Replace(string(raw), lines[3], strings.Replace(lines[3], "server.started", "server.stopped", 1), 1)
	os.WriteFile(todayFile(dir), []byte(edited), 0o600)
	if ok, _ := (&Store{dir: dir, max: 10}).verifyFresh(); ok {
		t.Fatal("edited accepted line not detected")
	}
	// So does a new break anywhere else.
	edited = strings.Replace(string(raw), `"i":4`, `"i":9`, 1)
	os.WriteFile(todayFile(dir), []byte(edited), 0o600)
	if ok, _ := (&Store{dir: dir, max: 10}).verifyFresh(); ok {
		t.Fatal("new break after accept not detected")
	}
	// And dropping the list.
	os.WriteFile(todayFile(dir), raw, 0o600)
	os.Remove(filepath.Join(dir, acceptedFile))
	if ok, _ := (&Store{dir: dir, max: 10}).verifyFresh(); ok {
		t.Fatal("removed ACCEPTED not detected")
	}
}

func TestAcceptChainBreaksNeedsReasonAndStoppedServer(t *testing.T) {
	root := t.TempDir()
	cfg := &Config{DataDir: root}
	if _, err := AcceptChainBreaks(cfg, "test", " "); err == nil {
		t.Fatal("accepted without a reason")
	}
	unlock, err := lockDataDir(root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := AcceptChainBreaks(cfg, "test", "x"); err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("ran beside a server: %v", err)
	}
}

func TestBackupCarriesAcceptedBreaks(t *testing.T) {
	cfg, cfgPath := backupFixture(t)
	key, pub := newKeys(t)
	events := filepath.Join(cfg.DataDir, "events")
	files, _ := filepath.Glob(filepath.Join(events, "*.jsonl"))
	raw, _ := os.ReadFile(files[len(files)-1])
	lines := strings.SplitAfter(string(raw), "\n")
	var cl chainLine
	json.Unmarshal([]byte(lines[0]), &cl)
	rec := []byte(`{"seq":99,"time":"2026-11-10T07:06:25Z","source":"server","event":{"type":"server.started","ts":"2026-11-10T07:06:25Z"}}`)
	fork, _ := json.Marshal(chainLine{Prev: cl.Prev, Hash: chainHash(cl.Prev, rec), Rec: rec})
	os.WriteFile(files[len(files)-1], []byte(string(fork)+"\n"+string(raw)), 0o600)

	var buf bytes.Buffer
	if _, err := WriteBackup(cfg, BackupOptions{ConfigPath: cfgPath, Recipient: pub}, &buf); err == nil {
		t.Fatal("backup of a broken chain written")
	}
	if _, err := AcceptChainBreaks(cfg, "test", "test fork"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if _, err := WriteBackup(cfg, BackupOptions{ConfigPath: cfgPath, Recipient: pub}, &buf); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBackup(bytes.NewReader(buf.Bytes()), key); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreBackup(bytes.NewReader(buf.Bytes()), key, RestoreOptions{DataDir: cfg.DataDir}); err != nil {
		t.Fatal(err)
	}
	st, _ := OpenStore(events, 10)
	if !st.ChainOK || st.Accepted == 0 {
		t.Fatalf("restored: ok=%v %q accepted=%d", st.ChainOK, st.ChainError, st.Accepted)
	}
}

func TestRingSlimAndByteCap(t *testing.T) {
	ports := make([]any, 50)
	for i := range ports {
		ports[i] = map[string]any{"port": i, "proto": "tcp", "addr": "0.0.0.0"}
	}
	r := ringSlim(Record{Event: proto.NewEvent("port.snapshot", map[string]any{"ports": ports, "host": "x"})})
	if r.Event.Data["ports_count"] != 50 || r.Event.Data["host"] != "x" || r.Event.Data["ports"] != nil {
		t.Fatalf("slimmed: %v", r.Event.Data)
	}
	var g ring
	for i := 0; i < 1000; i++ {
		g.add(Record{Seq: uint64(i)}, 1000, 10000, 100_000)
	}
	g.cut(10000, 100_000)
	if len(g.recs) != 100 || g.recs[99].Seq != 999 || g.bytes != 100_000 {
		t.Fatalf("ring: %d records, last %d, %d bytes", len(g.recs), g.recs[len(g.recs)-1].Seq, g.bytes)
	}
}

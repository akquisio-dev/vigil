package server

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Record is one entry of the event log. Every record is chained to the one
// before it by hash, across files, so deleting or editing a past record
// breaks every hash after it.
type Record struct {
	Seq    uint64      `json:"seq"`
	Time   time.Time   `json:"time"`
	Agent  string      `json:"agent,omitempty"`
	Source string      `json:"source"` // agent | server | admin
	Actor  string      `json:"actor,omitempty"`
	Event  proto.Event `json:"event"`
}

type chainLine struct {
	Hash string          `json:"hash"`
	Prev string          `json:"prev"`
	Rec  json.RawMessage `json:"rec"`
}

func chainHash(prev string, rec []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{'\n'})
	h.Write(rec)
	return hex.EncodeToString(h.Sum(nil))
}

type Store struct {
	dir string
	max int

	mu     sync.RWMutex
	seq    uint64
	head   string
	day    string
	file   *os.File
	recent ring
	needNL bool // the open day file ends in a cut line
	// maxBytes caps the window by encoded size (see ring); 0 means no cap.
	maxBytes int

	ChainOK    bool
	ChainError string
	// ChainWarning names lines that could not be read although the chain
	// runs on across them: a write cut off by a crash, which loses no
	// record from the chain. It does not make the chain unhealthy.
	ChainWarning string
	// Accepted counts breaks an operator accepted (see AcceptBreaks).
	Accepted   int
	VerifiedAt time.Time

	appendErr string // last failed write, cleared by the next good one

	// hooks are told about records after they are written (forwarding,
	// attack statistics). They are set before the server starts.
	hooks []func([]*Record)
}

// Health reports whether the log is intact and writable.
func (s *Store) Health() (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.ChainOK {
		return false, "event chain broken: " + s.ChainError
	}
	if s.appendErr != "" {
		return false, "event log not writable: " + s.appendErr
	}
	return true, ""
}

func OpenStore(dir string, recent int) (*Store, error) {
	return OpenStoreLimit(dir, recent, 0)
}

// OpenStoreLimit also caps the in-memory window at about maxBytes of
// encoded records.
func OpenStoreLimit(dir string, recent, maxBytes int) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, max: recent, maxBytes: maxBytes}
	s.verifyAndLoad()
	return s, nil
}

func (s *Store) files() []string {
	m, _ := filepath.Glob(filepath.Join(s.dir, "*.jsonl"))
	sort.Strings(m)
	return m
}

func (s *Store) anchor() string {
	raw, _ := os.ReadFile(filepath.Join(s.dir, "ANCHOR"))
	return strings.TrimSpace(string(raw))
}

// verifyAndLoad walks the whole retained chain. A broken chain is not
// repaired; the server keeps appending after the last record and reports
// the break, because the break itself is the evidence. Reading goes on
// after a bad line, so the head is always the last record on disk: a
// server that stopped at the bad line would chain every new record to an
// old one and fork the log on each restart.
func (s *Store) verifyAndLoad() {
	acc, accErr := loadAccepted(s.dir)
	v := &chainVerifier{prev: s.anchor(), accepted: acc}
	var g ring
	readErr := ""
	for _, f := range s.files() {
		name := filepath.Base(f)
		err := eachLine(f, func(n int, b []byte) {
			cl, ok := v.line(name, n, b)
			if !ok {
				return
			}
			var r Record
			if err := json.Unmarshal(cl.Rec, &r); err == nil {
				if r.Seq > s.seq {
					s.seq = r.Seq
				}
				g.add(ringSlim(r), ringSize(r.Event.Type, len(cl.Rec)), s.max, s.maxBytes)
			}
		})
		if err != nil && readErr == "" {
			readErr = fmt.Sprintf("%s: %v", name, err)
		}
	}
	g.cut(s.max, s.maxBytes)
	s.ChainError = v.err
	if s.ChainError == "" && accErr != nil {
		s.ChainError = accErr.Error()
	}
	if s.ChainError == "" {
		s.ChainError = readErr
	}
	s.ChainOK = s.ChainError == ""
	s.ChainWarning = ""
	if v.torn > 0 {
		s.ChainWarning = fmt.Sprintf("%d unreadable lines, first %s", v.torn, v.warning)
	}
	s.Accepted = v.acceptN
	s.head = v.prev
	s.recent = g
	s.VerifiedAt = time.Now().UTC()
}

// endsWithNewline reports whether a log file is empty or ends with a
// complete line. A server killed in the middle of a write leaves it
// without one.
func endsWithNewline(f *os.File) (bool, error) {
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return true, err
	}
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, fi.Size()-1); err != nil {
		return false, err
	}
	return b[0] == '\n', nil
}

// Verify re-reads the chain from disk.
func (s *Store) Verify() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		s.file.Sync()
	}
	seq, head := s.seq, s.head
	s.verifyAndLoad()
	if s.head != head && s.ChainOK {
		s.ChainOK = false
		s.ChainError = "head on disk differs from head in memory"
	}
	s.seq = max(s.seq, seq)
	return s.ChainOK, s.ChainError
}

func (s *Store) Append(recs ...*Record) error {
	s.mu.Lock()
	err := s.appendLocked(recs)
	s.appendErr = ""
	if err != nil {
		s.appendErr = err.Error()
	}
	hooks := s.hooks
	s.mu.Unlock()
	if err == nil {
		for _, h := range hooks {
			h(recs)
		}
	}
	return err
}

func (s *Store) appendLocked(recs []*Record) error {
	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	if s.file == nil || s.day != day {
		if s.file != nil {
			s.file.Close()
		}
		f, err := os.OpenFile(filepath.Join(s.dir, day+".jsonl"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		s.file, s.day = f, day
		s.needNL = false
		if ok, err := endsWithNewline(f); err != nil {
			return err
		} else if !ok {
			// Keep the next record off the cut line, so it stays readable
			// and the cut line is only that.
			s.needNL = true
		}
	}
	var buf []byte
	if s.needNL {
		buf = append(buf, '\n')
	}
	for _, r := range recs {
		s.seq++
		r.Seq = s.seq
		if r.Time.IsZero() {
			r.Time = now
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		cl := chainLine{Prev: s.head, Rec: raw}
		cl.Hash = chainHash(cl.Prev, raw)
		line, _ := json.Marshal(cl)
		buf = append(append(buf, line...), '\n')
		s.head = cl.Hash
		s.recent.add(ringSlim(*r), ringSize(r.Event.Type, len(raw)), s.max, s.maxBytes)
	}
	if _, err := s.file.Write(buf); err != nil {
		return err
	}
	s.needNL = false
	return s.file.Sync()
}

func (s *Store) Head() (uint64, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seq, s.head
}

type Query struct {
	Agent  string
	Agents map[string]bool // a group of hosts; nil means any
	Prefix string
	Before uint64
	Limit  int
}

// Recent returns newest first from the in-memory window.
func (s *Store) Recent(q Query) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	out := []Record{}
	for i := len(s.recent.recs) - 1; i >= 0 && len(out) < q.Limit; i-- {
		r := s.recent.recs[i]
		if q.Before > 0 && r.Seq >= q.Before {
			continue
		}
		if q.Agent != "" && r.Agent != q.Agent || q.Agents != nil && !q.Agents[r.Agent] {
			continue
		}
		if q.Prefix != "" && !strings.HasPrefix(r.Event.Type, q.Prefix) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Each visits the in-memory window oldest first.
func (s *Store) Each(fn func(Record)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.recent.recs {
		fn(r)
	}
}

// Prune deletes whole days past retention and moves the anchor forward so
// the remaining chain still verifies.
func (s *Store) Prune(days int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	for _, f := range s.files() {
		day := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		if day >= cutoff || day == s.day {
			break
		}
		last, err := lastHash(f)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(s.dir, "ANCHOR"), []byte(last+"\n"), 0o600); err != nil {
			return err
		}
		if err := os.Remove(f); err != nil {
			return err
		}
	}
	return nil
}

func lastHash(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 256*1024), proto.MaxBodyBytes*2)
	last := ""
	for sc.Scan() {
		v := chainVerifier{}
		if cl, ok := v.line("", 0, sc.Bytes()); ok {
			last = cl.Hash
		}
	}
	if last == "" {
		return "", errors.New("empty log file " + path)
	}
	return last, sc.Err()
}

// slim keeps bulky events out of the in-memory window: an evidence snapshot
// is up to 400 KB, and the window holds thousands of records. The views
// that show snapshots read them from disk.
func slim(r Record) Record {
	if r.Event.Type != "forensics.snapshot" || r.Event.Data == nil {
		return r
	}
	d := map[string]any{"slim": true}
	for _, k := range []string{"trigger", "pid", "request", "alert", "error", "sha256", "hostname"} {
		if v, ok := r.Event.Data[k]; ok {
			d[k] = v
		}
	}
	if t, ok := r.Event.Data["target"].(map[string]any); ok {
		d["exe"], d["exe_sha256"] = t["exe"], t["exe_sha256"]
	}
	r.Event.Data = d
	return r
}

// stateSync lists the events that carry a host's whole inventory (every
// listening port, every package). The server keeps the latest of each in
// its host state; in the event list they are only a marker that a report
// came, so the in-memory window keeps their scalar fields and the size of
// each list instead of the lists themselves.
var stateSync = map[string]bool{
	"port.snapshot": true, "container.snapshot": true, "posture.report": true,
	"system.packages": true, "system.apps": true, "secrets.scan": true,
	"suid.scan": true, "integrity.scan": true,
}

// ringSlim prepares a record for the in-memory window. Forwarding and the
// views that read from disk see the full record.
func ringSlim(r Record) Record {
	if !stateSync[r.Event.Type] || r.Event.Data == nil {
		return slim(r)
	}
	d := map[string]any{"slim": true}
	for k, v := range r.Event.Data {
		switch x := v.(type) {
		case []any:
			d[k+"_count"] = len(x)
		case map[string]any:
			d[k+"_count"] = len(x)
		default:
			d[k] = v
		}
	}
	r.Event.Data = d
	return r
}

// ring is the in-memory window: at most max records and about maxBytes of
// encoded size, whichever is reached first. It may grow to twice both before
// it is cut, so that cutting is rare.
type ring struct {
	recs  []Record
	sizes []int
	bytes int
}

func (g *ring) add(r Record, size, max, maxBytes int) {
	g.recs = append(g.recs, r)
	g.sizes = append(g.sizes, size)
	g.bytes += size
	if len(g.recs) > 2*max || maxBytes > 0 && g.bytes > 2*maxBytes {
		g.cut(max, maxBytes)
	}
}

// cut keeps the newest records within max and maxBytes, in fresh slices so
// the dropped records can be collected.
func (g *ring) cut(max, maxBytes int) {
	keep, b := 0, 0
	for i := len(g.recs) - 1; i >= 0 && keep < max; i-- {
		if maxBytes > 0 && b+g.sizes[i] > maxBytes && keep > 0 {
			break
		}
		b += g.sizes[i]
		keep++
	}
	from := len(g.recs) - keep
	g.recs = append([]Record(nil), g.recs[from:]...)
	g.sizes = append([]int(nil), g.sizes[from:]...)
	g.bytes = b
}

// ringSize estimates what a record costs in the window from the length of
// its encoded form (decoded maps cost a multiple of that, about the same
// for all). Slimmed records are small whatever they came from.
func ringSize(typ string, encoded int) int {
	if stateSync[typ] || typ == "forensics.snapshot" {
		return 256
	}
	return encoded
}

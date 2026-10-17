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
	recent []Record

	ChainOK    bool
	ChainError string
	VerifiedAt time.Time

	appendErr string // last failed write, cleared by the next good one
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, max: recent}
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
// the break, because the break itself is the evidence.
func (s *Store) verifyAndLoad() {
	prev := s.anchor()
	s.ChainOK, s.ChainError = true, ""
	var ring []Record
	for _, f := range s.files() {
		err := func() error {
			fh, err := os.Open(f)
			if err != nil {
				return err
			}
			defer fh.Close()
			sc := bufio.NewScanner(fh)
			sc.Buffer(make([]byte, 256*1024), proto.MaxBodyBytes*2)
			n := 0
			for sc.Scan() {
				n++
				var cl chainLine
				if err := json.Unmarshal(sc.Bytes(), &cl); err != nil {
					return fmt.Errorf("%s:%d: unreadable line", filepath.Base(f), n)
				}
				if s.ChainOK && (cl.Prev != prev || chainHash(cl.Prev, cl.Rec) != cl.Hash) {
					s.ChainOK = false
					s.ChainError = fmt.Sprintf("%s:%d: hash chain broken", filepath.Base(f), n)
				}
				var r Record
				if err := json.Unmarshal(cl.Rec, &r); err == nil {
					if r.Seq > s.seq {
						s.seq = r.Seq
					}
					ring = append(ring, slim(r))
					if len(ring) > s.max*2 {
						ring = append([]Record{}, ring[len(ring)-s.max:]...)
					}
				}
				prev = cl.Hash
			}
			return sc.Err()
		}()
		if err != nil && s.ChainOK {
			s.ChainOK = false
			s.ChainError = err.Error()
		}
	}
	if len(ring) > s.max {
		ring = ring[len(ring)-s.max:]
	}
	s.head = prev
	s.recent = ring
	s.VerifiedAt = time.Now().UTC()
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
	defer s.mu.Unlock()
	err := s.appendLocked(recs)
	s.appendErr = ""
	if err != nil {
		s.appendErr = err.Error()
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
		f, err := os.OpenFile(filepath.Join(s.dir, day+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		s.file, s.day = f, day
	}
	var buf []byte
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
		s.recent = append(s.recent, slim(*r))
	}
	if len(s.recent) > s.max*2 {
		s.recent = append([]Record{}, s.recent[len(s.recent)-s.max:]...)
	}
	if _, err := s.file.Write(buf); err != nil {
		return err
	}
	return s.file.Sync()
}

func (s *Store) Head() (uint64, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.seq, s.head
}

type Query struct {
	Agent  string
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
	for i := len(s.recent) - 1; i >= 0 && len(out) < q.Limit; i-- {
		r := s.recent[i]
		if q.Before > 0 && r.Seq >= q.Before {
			continue
		}
		if q.Agent != "" && r.Agent != q.Agent {
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
	for _, r := range s.recent {
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
		var cl chainLine
		if json.Unmarshal(sc.Bytes(), &cl) == nil {
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

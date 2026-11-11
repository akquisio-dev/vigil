package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// acceptedFile lists chain breaks an operator looked at and accepted, one
// JSON object per line. It lives next to the event log, and every entry is
// pinned to the exact bytes of the broken line: changing that line again,
// or any other break, still breaks the chain.
const acceptedFile = "ACCEPTED"

// AcceptedBreak is one accepted break.
type AcceptedBreak struct {
	File   string    `json:"file"`
	Line   int       `json:"line"`
	SHA256 string    `json:"sha256"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
}

func (b AcceptedBreak) key() string { return fmt.Sprintf("%s:%d:%s", b.File, b.Line, b.SHA256) }

// loadAccepted reads the accepted breaks and the SHA-256 of the file.
func loadAccepted(dir string) (map[string]bool, string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, acceptedFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	m, err := parseAccepted(raw)
	return m, hex.EncodeToString(sum[:]), err
}

func parseAccepted(raw []byte) (map[string]bool, error) {
	m := map[string]bool{}
	for i, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var b AcceptedBreak
		if err := json.Unmarshal(line, &b); err != nil || b.File == "" || b.Line <= 0 || len(b.SHA256) != 64 {
			return nil, fmt.Errorf("%s:%d: unreadable entry", acceptedFile, i+1)
		}
		m[b.key()] = true
	}
	return m, nil
}

// chainVerifier follows the hash chain line by line. The store and the
// backup both use it, so a log that opens also backs up.
//
// A line that cannot be read is a write cut off by a crash, not a break by
// itself: if a record was lost, the next line does not chain to the one
// before and that is the break. When a server restarted after such a crash
// and appended to the cut line, the line holds the cut part followed by a
// whole record, and that record is read and checked like any other.
type chainVerifier struct {
	prev     string
	accepted map[string]bool

	err      string // first break that is not accepted
	warning  string // first unreadable line
	torn     int
	acceptN  int
	breaks   []AcceptedBreak // breaks not accepted, at most maxBreaks
	overflow bool
}

const maxBreaks = 100000

// line checks one line and returns it when it holds a record.
func (v *chainVerifier) line(file string, n int, b []byte) (chainLine, bool) {
	var cl chainLine
	if err := json.Unmarshal(b, &cl); err != nil {
		v.torn++
		if v.warning == "" {
			v.warning = fmt.Sprintf("%s:%d: unreadable line (a write cut off by a crash)", file, n)
		}
		i := bytes.LastIndex(b, []byte(`{"hash":"`))
		if i <= 0 || json.Unmarshal(b[i:], &cl) != nil {
			return cl, false
		}
	}
	if cl.Prev != v.prev || chainHash(cl.Prev, cl.Rec) != cl.Hash {
		sum := sha256.Sum256(b)
		br := AcceptedBreak{File: file, Line: n, SHA256: hex.EncodeToString(sum[:])}
		if v.accepted[br.key()] {
			v.acceptN++
		} else {
			if v.err == "" {
				v.err = fmt.Sprintf("%s:%d: hash chain broken", file, n)
			}
			if len(v.breaks) < maxBreaks {
				v.breaks = append(v.breaks, br)
			} else {
				v.overflow = true
			}
		}
	}
	v.prev = cl.Hash
	return cl, true
}

// AcceptBreaks records every break the chain has now as accepted, writes a
// chain.accepted record that says who did it and why, and verifies again.
// It is for a break whose cause is known, such as a server killed in a
// loop; the record and its alert are the trace that it was done. Only the
// command line offers it, with the server stopped.
func (s *Store) AcceptBreaks(by, reason string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	breaks, overflow, err := s.scanBreaks()
	if err != nil {
		return 0, err
	}
	if overflow {
		return 0, fmt.Errorf("more than %d breaks; this is not a crash, look at the log", maxBreaks)
	}
	if len(breaks) == 0 {
		return 0, nil
	}
	now := time.Now().UTC()
	var buf []byte
	for _, b := range breaks {
		b.At, b.By = now, by
		line, _ := json.Marshal(b)
		buf = append(append(buf, line...), '\n')
	}
	f, err := os.OpenFile(filepath.Join(s.dir, acceptedFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		return 0, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	first, last := breaks[0], breaks[len(breaks)-1]
	err = s.appendLocked([]*Record{{Source: "admin", Actor: by, Event: proto.NewEvent("chain.accepted", map[string]any{
		"count": len(breaks), "first": fmt.Sprintf("%s:%d", first.File, first.Line),
		"last": fmt.Sprintf("%s:%d", last.File, last.Line), "reason": reason,
	})}})
	if err != nil {
		return 0, err
	}
	s.verifyAndLoad()
	if !s.ChainOK {
		return len(breaks), errors.New("still broken after accepting: " + s.ChainError)
	}
	return len(breaks), nil
}

// scanBreaks walks the chain once more and returns its unaccepted breaks.
func (s *Store) scanBreaks() ([]AcceptedBreak, bool, error) {
	acc, _, err := loadAccepted(s.dir)
	if err != nil {
		return nil, false, err
	}
	v := &chainVerifier{prev: s.anchor(), accepted: acc}
	for _, f := range s.files() {
		if err := eachLine(f, func(n int, b []byte) { v.line(filepath.Base(f), n, b) }); err != nil {
			return nil, false, err
		}
	}
	return v.breaks, v.overflow, nil
}

// eachLine calls fn for every line of a log file, numbered from 1.
func eachLine(path string, fn func(int, []byte)) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 256*1024), proto.MaxBodyBytes*2)
	n := 0
	for sc.Scan() {
		n++
		fn(n, sc.Bytes())
	}
	return sc.Err()
}

// AcceptChainBreaks is AcceptBreaks for the command line. It takes the data
// directory lock, so it refuses while the server runs, and leaves the files
// it wrote owned like the data directory.
func AcceptChainBreaks(cfg *Config, by, reason string) (int, error) {
	if strings.TrimSpace(reason) == "" {
		return 0, errors.New("say why with -reason; it goes into the event log")
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return 0, err
	}
	defer unlock()
	st, err := OpenStore(filepath.Join(cfg.DataDir, "events"), 1)
	if err != nil {
		return 0, err
	}
	n, err := st.AcceptBreaks(by, reason)
	if st.file != nil {
		st.file.Close()
	}
	if uid, gid, ok := dataOwner(cfg.DataDir); ok {
		for _, p := range []string{filepath.Join(st.dir, acceptedFile), filepath.Join(st.dir, st.day+".jsonl")} {
			if _, serr := os.Stat(p); serr == nil {
				os.Chown(p, uid, gid)
			}
		}
	}
	return n, err
}

// Package osv matches application dependencies (npm, PyPI, Go modules)
// against the OSV.dev vulnerability data.
//
// The data comes from OSV's public dumps, one zip per ecosystem, and is kept
// up to date record by record through the ecosystem's modified_id.csv. No
// package name ever leaves the server: nothing is looked up through the
// query API. A dump is reduced to one line per affected package
// ("name<TAB>entry json") in a gzip file, which is scanned again only for
// the names the hosts actually have.
package osv

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	NPM  = "npm"
	PyPI = "PyPI"
	Go   = "Go"
)

// Ecosystems are the OSV ecosystems vigil reads.
var Ecosystems = []string{NPM, PyPI, Go}

// Entry is one vulnerability as it applies to one package.
type Entry struct {
	ID       string    `json:"id"`
	Aliases  []string  `json:"a,omitempty"` // CVE and GHSA ids
	Severity string    `json:"s,omitempty"` // low | medium | high | critical, empty if unknown
	Summary  string    `json:"t,omitempty"`
	Modified string    `json:"m,omitempty"`
	Ranges   [][]Event `json:"r,omitempty"`
	Versions []string  `json:"v,omitempty"`
}

type Event struct {
	Introduced   string `json:"i,omitempty"`
	Fixed        string `json:"f,omitempty"`
	LastAffected string `json:"l,omitempty"`
}

// Malicious tells a known malicious package (OSV's MAL- records) from a
// flaw in a legitimate one.
func (e *Entry) Malicious() bool { return strings.HasPrefix(e.ID, "MAL-") }

// CVEs are the entry's own id and aliases that name a CVE.
func (e *Entry) CVEs() []string {
	var out []string
	for _, id := range append([]string{e.ID}, e.Aliases...) {
		if strings.HasPrefix(id, "CVE-") {
			out = append(out, id)
		}
	}
	return out
}

// Affects reports whether version is affected. A version that cannot be
// read is not affected, unless the entry lists no versions at all, which
// OSV uses for a package that is malicious in every version.
func (e *Entry) Affects(eco, version string) bool {
	if len(e.Ranges) == 0 && len(e.Versions) == 0 {
		return true
	}
	for _, v := range e.Versions {
		if c, ok := Compare(eco, v, version); ok && c == 0 {
			return true
		} else if !ok && v == version {
			return true
		}
	}
	for _, r := range e.Ranges {
		if inRange(eco, r, version) {
			return true
		}
	}
	return false
}

// inRange follows the OSV algorithm: walk the events in version order and
// flip between affected and not affected at each one at or below version.
func inRange(eco string, evs []Event, version string) bool {
	type ev struct {
		v    string
		kind byte
	}
	var list []ev
	for _, e := range evs {
		switch {
		case e.Introduced != "":
			list = append(list, ev{e.Introduced, 'i'})
		case e.Fixed != "":
			list = append(list, ev{e.Fixed, 'f'})
		case e.LastAffected != "":
			list = append(list, ev{e.LastAffected, 'l'})
		}
	}
	less := func(a, b string) bool {
		if a == "0" {
			return b != "0"
		}
		if b == "0" {
			return false
		}
		c, _ := Compare(eco, a, b)
		return c < 0
	}
	sort.SliceStable(list, func(i, j int) bool { return less(list[i].v, list[j].v) })
	affected := false
	for _, e := range list {
		c := 1
		if e.v != "0" {
			var ok bool
			if c, ok = Compare(eco, version, e.v); !ok {
				return false
			}
		}
		switch e.kind {
		case 'i':
			if c >= 0 {
				affected = true
			}
		case 'f':
			if c >= 0 {
				affected = false
			}
		case 'l':
			if c > 0 {
				affected = false
			}
		}
	}
	return affected
}

// FixedAfter is the lowest fixed version above version, or "".
func (e *Entry) FixedAfter(eco, version string) string {
	best := ""
	for _, r := range e.Ranges {
		for _, ev := range r {
			if ev.Fixed == "" {
				continue
			}
			if c, ok := Compare(eco, ev.Fixed, version); !ok || c <= 0 {
				continue
			}
			if c, ok := Compare(eco, ev.Fixed, best); best == "" || (ok && c < 0) {
				best = ev.Fixed
			}
		}
	}
	return best
}

// record is the part of an OSV record vigil reads.
type record struct {
	ID        string   `json:"id"`
	Modified  string   `json:"modified"`
	Withdrawn string   `json:"withdrawn"`
	Aliases   []string `json:"aliases"`
	Summary   string   `json:"summary"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		Versions         []string `json:"versions"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// Parse reads one OSV record and returns its entries for eco, by package
// name. A withdrawn record returns withdrawn true and no entries.
func Parse(raw []byte, eco string) (id string, entries map[string]*Entry, withdrawn bool, err error) {
	var r record
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", nil, false, err
	}
	if r.ID == "" {
		return "", nil, false, errors.New("record without id")
	}
	if r.Withdrawn != "" {
		return r.ID, nil, true, nil
	}
	sev := level(r.DatabaseSpecific.Severity)
	for _, s := range r.Severity {
		if sev != "" {
			break
		}
		if strings.HasPrefix(s.Type, "CVSS_V3") {
			if score, ok := CVSS3(s.Score); ok {
				sev = scoreLevel(score)
			}
		}
	}
	var aliases []string
	for _, a := range r.Aliases {
		if strings.HasPrefix(a, "CVE-") || strings.HasPrefix(a, "GHSA-") {
			aliases = append(aliases, a)
		}
	}
	summary := r.Summary
	if len(summary) > 160 {
		summary = summary[:160]
	}
	entries = map[string]*Entry{}
	for _, af := range r.Affected {
		if af.Package.Ecosystem != eco || af.Package.Name == "" {
			continue
		}
		name := NormalizeName(eco, af.Package.Name)
		e := entries[name]
		if e == nil {
			e = &Entry{ID: r.ID, Aliases: aliases, Severity: sev, Summary: summary, Modified: r.Modified}
			entries[name] = e
		}
		if s := level(af.DatabaseSpecific.Severity); e.Severity == "" && s != "" {
			e.Severity = s
		}
		for _, rg := range af.Ranges {
			if rg.Type != "SEMVER" && rg.Type != "ECOSYSTEM" {
				continue
			}
			var evs []Event
			for _, ev := range rg.Events {
				evs = append(evs, Event{Introduced: ev.Introduced, Fixed: ev.Fixed, LastAffected: ev.LastAffected})
			}
			e.Ranges = append(e.Ranges, evs)
		}
		e.Versions = append(e.Versions, af.Versions...)
		if len(e.Ranges) > 0 && len(e.Versions) > 0 {
			// The ranges say the same and are much shorter.
			e.Versions = nil
		}
	}
	if strings.HasPrefix(r.ID, "MAL-") {
		for _, e := range entries {
			e.Severity = "critical"
		}
	}
	return r.ID, entries, false, nil
}

func level(s string) string {
	switch strings.ToUpper(s) {
	case "LOW":
		return "low"
	case "MODERATE", "MEDIUM":
		return "medium"
	case "HIGH":
		return "high"
	case "CRITICAL":
		return "critical"
	}
	return ""
}

func scoreLevel(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	case s > 0:
		return "low"
	}
	return ""
}

// CVSS3 computes the base score of a CVSS 3.0 or 3.1 vector.
func CVSS3(vector string) (float64, bool) {
	m := map[string]string{}
	for _, p := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(p, ":"); ok {
			m[k] = v
		}
	}
	w := func(metric string, table map[string]float64) (float64, bool) {
		x, ok := table[m[metric]]
		return x, ok
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	av, ok1 := w("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := w("AC", map[string]float64{"L": 0.77, "H": 0.44})
	ui, ok3 := w("UI", map[string]float64{"N": 0.85, "R": 0.62})
	c, ok4 := w("C", cia)
	i, ok5 := w("I", cia)
	a, ok6 := w("A", cia)
	changed := m["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	p, ok7 := w("PR", pr)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) || (m["S"] != "U" && !changed) {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * av * ac * p * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10)), true
	}
	return roundUp(math.Min(impact+expl, 10)), true
}

// roundUp is CVSS 3.1's Roundup: the smallest one-decimal number not below x.
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}

// BuildIndex turns the dump all.zip of eco, read as a stream, into the
// index format: one line per package and entry. The zip is read entry by
// entry from its local headers, so neither the 200 MB file nor its central
// directory (one header per record) is ever held. A stream that ends before
// the central directory is cut off and fails.
func BuildIndex(r io.Reader, eco string, w io.Writer) (int, error) {
	gz := gzip.NewWriter(w)
	bw := bufio.NewWriter(gz)
	n := 0
	err := walkZip(r, func(name string, raw []byte) error {
		if !strings.HasSuffix(name, ".json") {
			return nil
		}
		_, entries, withdrawn, err := Parse(raw, eco)
		if err != nil || withdrawn {
			return nil
		}
		for pkg, e := range entries {
			if err := writeLine(bw, pkg, e); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return n, err
	}
	if err := bw.Flush(); err != nil {
		return n, err
	}
	return n, gz.Close()
}

const maxRecord = 8 << 20

var errCutOff = errors.New("zip ends before its central directory (cut off)")

// walkZip calls fn for each file of a zip stream, in order, with its
// checked contents.
func walkZip(r io.Reader, fn func(name string, data []byte) error) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var hdr [30]byte
	for {
		if _, err := io.ReadFull(br, hdr[:4]); err != nil {
			return errCutOff
		}
		switch binary.LittleEndian.Uint32(hdr[:4]) {
		case 0x04034b50:
		case 0x02014b50, 0x06054b50:
			return nil // central directory: every file was read
		default:
			return errors.New("zip: unexpected header")
		}
		if _, err := io.ReadFull(br, hdr[4:]); err != nil {
			return errCutOff
		}
		flags := binary.LittleEndian.Uint16(hdr[6:])
		method := binary.LittleEndian.Uint16(hdr[8:])
		crc := binary.LittleEndian.Uint32(hdr[14:])
		csize := int64(binary.LittleEndian.Uint32(hdr[18:]))
		usize := int64(binary.LittleEndian.Uint32(hdr[22:]))
		meta := make([]byte, int(binary.LittleEndian.Uint16(hdr[26:]))+int(binary.LittleEndian.Uint16(hdr[28:])))
		if _, err := io.ReadFull(br, meta); err != nil {
			return errCutOff
		}
		name := string(meta[:binary.LittleEndian.Uint16(hdr[26:])])
		descriptor := flags&8 != 0
		if !descriptor && (csize == 0xffffffff || usize == 0xffffffff) {
			return errors.New("zip: zip64 entries are not supported")
		}
		if descriptor && method != 8 {
			return errors.New("zip: stored entry without sizes")
		}
		var raw io.Reader = br
		var lr *io.LimitedReader
		if !descriptor {
			lr = &io.LimitedReader{R: br, N: csize}
			raw = lr
		}
		var body io.Reader
		switch method {
		case 0:
			body = raw
		case 8:
			// From a ByteReader (descriptor case) flate takes no byte
			// past the end of its stream.
			body = flate.NewReader(raw)
		default:
			return fmt.Errorf("zip: %s: method %d", name, method)
		}
		h := crc32.NewIEEE()
		tee := io.TeeReader(body, h)
		data, err := io.ReadAll(io.LimitReader(tee, maxRecord+1))
		if err == nil && len(data) > maxRecord {
			// Too large for a record: hashed and skipped, not kept.
			var rest int64
			rest, err = io.Copy(io.Discard, tee)
			usize -= rest
			data = nil
		}
		if err != nil {
			return errCutOff
		}
		if lr != nil {
			if _, err := io.Copy(io.Discard, lr); err != nil || lr.N != 0 {
				return errCutOff
			}
		}
		if descriptor {
			var d [12]byte
			if _, err := io.ReadFull(br, d[:4]); err != nil {
				return errCutOff
			}
			if binary.LittleEndian.Uint32(d[:4]) == 0x08074b50 {
				if _, err := io.ReadFull(br, d[:4]); err != nil {
					return errCutOff
				}
			}
			if _, err := io.ReadFull(br, d[4:12]); err != nil {
				return errCutOff
			}
			crc = binary.LittleEndian.Uint32(d[:4])
			usize = int64(binary.LittleEndian.Uint32(d[8:12]))
		}
		if h.Sum32() != crc {
			return fmt.Errorf("zip: %s is damaged", name)
		}
		if data == nil {
			continue
		}
		if int64(len(data)) != usize {
			return fmt.Errorf("zip: %s is damaged", name)
		}
		if err := fn(name, data); err != nil {
			return err
		}
	}
}

func writeLine(w io.Writer, name string, e *Entry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if strings.ContainsAny(name, "\t\n") {
		return nil
	}
	_, err = io.WriteString(w, name+"\t"+string(b)+"\n")
	return err
}

// Overlay holds the records changed since the index was built, by id. A
// record with no entries was withdrawn or no longer names a package of
// the ecosystem.
type Overlay struct {
	Synced  time.Time                    `json:"synced"` // newest modified time applied
	Records map[string]map[string]*Entry `json:"records"`
}

// Scan reads the index and returns the entries for the given names, with
// the overlay applied over it.
func Scan(index io.Reader, ov *Overlay, names map[string]bool) (map[string][]*Entry, error) {
	gz, err := gzip.NewReader(index)
	if err != nil {
		return nil, err
	}
	out := map[string][]*Entry{}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		tab := strings.IndexByte(string(line[:min(len(line), 300)]), '\t')
		if tab < 0 || !names[string(line[:tab])] {
			continue
		}
		var e Entry
		if json.Unmarshal(line[tab+1:], &e) != nil {
			continue
		}
		if ov != nil {
			if _, changed := ov.Records[e.ID]; changed {
				continue
			}
		}
		out[string(line[:tab])] = append(out[string(line[:tab])], &e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if ov != nil {
		for _, recs := range ov.Records {
			for name, e := range recs {
				if names[name] {
					out[name] = append(out[name], e)
				}
			}
		}
	}
	return out, nil
}

// Changed reads modified_id.csv (newest first) and returns the ids changed
// after since, stopping at the first older line. complete is false when
// the reader ended before that line, so more of the file is needed.
func Changed(r io.Reader, since time.Time) (ids []string, newest time.Time, complete bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		ts, id, ok := strings.Cut(sc.Text(), ",")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		if !t.After(since) {
			return ids, newest, true
		}
		if t.After(newest) {
			newest = t
		}
		ids = append(ids, strings.TrimSpace(id))
	}
	return ids, newest, false
}

// Score names an entry's weight for sorting: severity, malicious first.
func Score(e *Entry) int {
	if e.Malicious() {
		return 5
	}
	n, _ := strconv.Atoi(map[string]string{"critical": "4", "high": "3", "medium": "2", "low": "1"}[e.Severity])
	return n
}

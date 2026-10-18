package server

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akquisio-dev/vigil/internal/dpkgver"
)

// Vulnerability matching (vuln_lookup). Agents send their installed source
// packages; the server matches them against the distributions' own security
// data and against CISA's catalogue of vulnerabilities known to be
// exploited. Sources: Canonical's OVAL feed per Ubuntu release (about 10 MB)
// and the Debian security tracker (about 14 MB for all releases), both
// fetched at most daily and only when they changed. The server only
// downloads; nothing about the hosts or their packages leaves it.

const (
	ubuntuOVAL   = "https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2"
	debianJSON   = "https://security-tracker.debian.org/tracker/data/json"
	kevURL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	vulnRefresh  = 20 * time.Hour
	vulnMaxBytes = 256 << 20
)

type vulnPkg struct {
	Name     string `json:"n"`
	Fixed    string `json:"f,omitempty"` // empty: no fix released
	Severity string `json:"s,omitempty"`
	Pro      bool   `json:"p,omitempty"` // fix only with an Ubuntu Pro subscription
}

type vulnRec struct {
	CVE  string    `json:"c"`
	Pkgs []vulnPkg `json:"p"`
}

// vulnIndex holds the vulnerabilities of one release ("ubuntu:noble",
// "debian:bookworm"), by CVE.
type vulnIndex struct {
	Release string              `json:"release"`
	Updated time.Time           `json:"updated"` // when the source was last fetched
	Source  time.Time           `json:"source"`  // Last-Modified of the source
	Recs    map[string]*vulnRec `json:"recs"`

	byPkg map[string][]*vulnRec
	// kept is set on an index reduced to the packages installed on the
	// hosts (in memory only; the file on disk stays complete).
	kept map[string]bool
}

// prune keeps the vulnerabilities of the named packages. Most of a
// release's data is about packages no host has (dozens of kernel flavours
// for every kernel flaw), and dropping it keeps the server small.
func (vi *vulnIndex) prune(names map[string]bool) *vulnIndex {
	out := &vulnIndex{Release: vi.Release, Updated: vi.Updated, Source: vi.Source, Recs: map[string]*vulnRec{}, kept: names}
	for id, r := range vi.Recs {
		var pk []vulnPkg
		for _, p := range r.Pkgs {
			if names[p.Name] {
				pk = append(pk, p)
			}
		}
		if len(pk) > 0 {
			out.Recs[id] = &vulnRec{CVE: r.CVE, Pkgs: pk}
		}
	}
	out.build()
	return out
}

// installedNames are the source packages of all hosts on a release. Caller
// holds s.mu.
func (s *Server) installedNames(rel string) map[string]bool {
	names := map[string]bool{}
	for _, p := range s.pkgs {
		if p.Eco == rel {
			for _, kv := range p.List {
				names[kv[0]] = true
			}
		}
	}
	return names
}

func (vi *vulnIndex) build() {
	vi.byPkg = map[string][]*vulnRec{}
	for _, r := range vi.Recs {
		seen := map[string]bool{}
		for _, p := range r.Pkgs {
			if !seen[p.Name] {
				seen[p.Name] = true
				vi.byPkg[p.Name] = append(vi.byPkg[p.Name], r)
			}
		}
	}
}

func (vi *vulnIndex) add(cve string, p vulnPkg) {
	r := vi.Recs[cve]
	if r == nil {
		r = &vulnRec{CVE: cve}
		vi.Recs[cve] = r
	}
	r.Pkgs = append(r.Pkgs, p)
}

type vulnDB struct {
	mu      sync.RWMutex
	idx     map[string]*vulnIndex
	kev     map[string]bool
	kevTime time.Time
	errs    map[string]string
	running atomic.Bool
	again   atomic.Bool // a refresh was asked for while one was running
}

type agentPackages struct {
	Eco      string      `json:"release"`
	OS       string      `json:"os"`
	Received time.Time   `json:"received"`
	List     [][2]string `json:"packages"`
}

type VulnHit struct {
	CVE       string `json:"cve"`
	Package   string `json:"package"`
	Installed string `json:"installed"`
	Fixed     string `json:"fixed,omitempty"`
	Severity  string `json:"severity"`
	Pro       bool   `json:"pro,omitempty"`
	KEV       bool   `json:"kev,omitempty"`
}

type VulnSummary struct {
	Ecosystem string         `json:"release"`
	Checked   time.Time      `json:"checked"`
	Packages  int            `json:"packages"`
	Fixable   map[string]int `json:"fixable"`
	Unfixed   map[string]int `json:"unfixed"`
	Exploited []VulnHit      `json:"exploited,omitempty"`
	Top       []VulnHit      `json:"top,omitempty"`
	Error     string         `json:"error,omitempty"`
}

var codenames = map[string]string{
	"debian:10": "buster", "debian:11": "bullseye", "debian:12": "bookworm", "debian:13": "trixie", "debian:14": "forky",
	"ubuntu:18.04": "bionic", "ubuntu:20.04": "focal", "ubuntu:22.04": "jammy", "ubuntu:24.04": "noble",
	"ubuntu:24.10": "oracular", "ubuntu:25.04": "plucky", "ubuntu:25.10": "questing",
}

var codenameRe = regexp.MustCompile(`^[a-z]{3,20}$`)

// releaseKey names a host's release from /etc/os-release: "ubuntu:noble".
func releaseKey(id, version, codename string) string {
	if id != "ubuntu" && id != "debian" {
		return ""
	}
	if codename == "" {
		major := version
		if id == "debian" {
			major, _, _ = strings.Cut(version, ".")
		}
		codename = codenames[id+":"+major]
	}
	if !codenameRe.MatchString(codename) {
		return ""
	}
	return id + ":" + codename
}

var severityOrder = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}

func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "*"))
	switch s {
	case "critical", "high", "medium", "low":
		return s
	case "negligible", "unimportant":
		return "negligible"
	}
	return "unknown"
}

func scoreSeverity(s float64) string {
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
	return "unknown"
}

// Canonical's OVAL criteria name the source package and its state:
// "openssh source package in noble, is affected and has been fixed (note: '1:9.6p1-3ubuntu13.3')."
// "swish-e source package in esm-apps/noble, might be affected and may need fixing."
var ovalCriterion = regexp.MustCompile(`^(\S+) source package in (\S+), (.*?)(?: \(note: '([^']*)'\))?\.?$`)

// Kernels have their own form, one per flavour (linux, linux-aws, ...):
// "'linux' kernel in noble was vulnerable but has been fixed (note: '6.8.0-35.35')."
var ovalKernel = regexp.MustCompile(`^'([a-z0-9.-]+)' kernel in (\S+) was vulnerable but has been fixed \(note: '([^']+)'\)`)

// parseOVAL reads one release's CVE OVAL feed.
func parseOVAL(r io.Reader, release string) (*vulnIndex, error) {
	vi := &vulnIndex{Release: release, Recs: map[string]*vulnRec{}}
	dec := xml.NewDecoder(r)
	var cve, prio string
	var score float64
	var crits []string
	inDef := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "definition":
				inDef, cve, prio, score, crits = true, "", "", 0, nil
			case "cve":
				if !inDef {
					continue
				}
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "priority":
						prio = a.Value
					case "cvss_score":
						score, _ = strconv.ParseFloat(a.Value, 64)
					}
				}
				var text string
				if dec.DecodeElement(&text, &t) == nil {
					cve = strings.TrimSpace(text)
				}
			case "criterion":
				if !inDef {
					continue
				}
				for _, a := range t.Attr {
					if a.Name.Local == "comment" {
						crits = append(crits, a.Value)
					}
				}
			}
		case xml.EndElement:
			if t.Name.Local != "definition" || !inDef {
				continue
			}
			inDef = false
			if !strings.HasPrefix(cve, "CVE-") {
				continue
			}
			sev := normSeverity(prio)
			if sev == "unknown" {
				sev = scoreSeverity(score)
			}
			for _, c := range crits {
				if k := ovalKernel.FindStringSubmatch(c); k != nil {
					vi.add(cve, vulnPkg{Name: k[1], Fixed: k[3], Severity: sev, Pro: strings.HasPrefix(k[2], "esm-")})
					continue
				}
				m := ovalCriterion.FindStringSubmatch(c)
				if m == nil || strings.Contains(m[3], "not affected") {
					continue
				}
				p := vulnPkg{Name: m[1], Severity: sev, Pro: strings.HasPrefix(m[2], "esm-")}
				if strings.Contains(m[3], "has been fixed") {
					p.Fixed = m[4]
					if p.Fixed == "" {
						continue
					}
				}
				vi.add(cve, p)
			}
		}
	}
	if len(vi.Recs) == 0 {
		return nil, fmt.Errorf("no vulnerabilities in the %s feed", release)
	}
	return vi, nil
}

// parseDebian reads the security tracker's JSON (package -> CVE -> release)
// for the given codenames, one package at a time.
func parseDebian(r io.Reader, want map[string]bool) (map[string]*vulnIndex, error) {
	out := map[string]*vulnIndex{}
	for c := range want {
		out[c] = &vulnIndex{Release: "debian:" + c, Recs: map[string]*vulnRec{}}
	}
	dec := json.NewDecoder(r)
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("tracker data is not an object")
	}
	type rel struct {
		Status  string `json:"status"`
		Fixed   string `json:"fixed_version"`
		Urgency string `json:"urgency"`
	}
	type entry struct {
		Releases map[string]rel `json:"releases"`
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		pkg, _ := t.(string)
		var cves map[string]entry
		if err := dec.Decode(&cves); err != nil {
			return nil, err
		}
		for cve, e := range cves {
			if !strings.HasPrefix(cve, "CVE-") {
				continue
			}
			for code, rl := range e.Releases {
				vi := out[code]
				if vi == nil {
					continue
				}
				p := vulnPkg{Name: pkg, Severity: normSeverity(rl.Urgency)}
				switch rl.Status {
				case "resolved":
					if rl.Fixed == "" || rl.Fixed == "0" {
						continue // never affected
					}
					p.Fixed = rl.Fixed
				case "open", "undetermined":
				default:
					continue
				}
				vi.add(cve, p)
			}
		}
	}
	for c, vi := range out {
		if len(vi.Recs) == 0 {
			return nil, fmt.Errorf("no vulnerabilities for debian %s", c)
		}
	}
	return out, nil
}

func (s *Server) vulnDir() string { return filepath.Join(s.cfg.DataDir, "vuln") }

func ecoFile(rel string) string { return strings.NewReplacer(":", "_", "/", "_").Replace(rel) }

func (s *Server) loadIndex(rel string) *vulnIndex {
	f, err := os.Open(filepath.Join(s.vulnDir(), ecoFile(rel)+".json.gz"))
	if err != nil {
		return nil
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	var vi vulnIndex
	if json.NewDecoder(zr).Decode(&vi) != nil || vi.Release != rel {
		return nil
	}
	if vi.Recs == nil {
		vi.Recs = map[string]*vulnRec{}
	}
	vi.build()
	return &vi
}

func (s *Server) saveIndex(vi *vulnIndex) error {
	if vi.kept != nil {
		return fmt.Errorf("%s: a reduced index is not written to disk", vi.Release)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(vi); err != nil {
		return err
	}
	zw.Close()
	return writeAtomic(filepath.Join(s.vulnDir(), ecoFile(vi.Release)+".json.gz"), buf.Bytes())
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// vulnFetch downloads u into a temp file unless it is unchanged since
// `since`. It returns the open file (nil when unchanged) and Last-Modified.
func (s *Server) vulnFetch(u string, since time.Time) (*os.File, time.Time, error) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "vigil/"+Version+" (+https://github.com/akquisio-dev/vigil)")
	if !since.IsZero() {
		req.Header.Set("If-Modified-Since", since.UTC().Format(http.TimeFormat))
	}
	res, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotModified {
		return nil, since, nil
	}
	if res.StatusCode != 200 {
		return nil, time.Time{}, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	lm, err := http.ParseTime(res.Header.Get("Last-Modified"))
	if err != nil {
		lm = time.Now().UTC()
	}
	f, err := os.CreateTemp(s.vulnDir(), "download-*")
	if err != nil {
		return nil, time.Time{}, err
	}
	os.Remove(f.Name()) // gone when closed
	n, err := io.Copy(f, io.LimitReader(res.Body, vulnMaxBytes+1))
	if err == nil && n > vulnMaxBytes {
		err = fmt.Errorf("larger than %d bytes", vulnMaxBytes)
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, time.Time{}, err
	}
	return f, lm.UTC(), nil
}

func vulnGet(c *http.Client, u string, limit int64, w io.Writer) error {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "vigil/"+Version+" (+https://github.com/akquisio-dev/vigil)")
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", res.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(res.Body, limit+1))
	if err == nil && n > limit {
		err = fmt.Errorf("larger than %d bytes", limit)
	}
	return err
}

func (s *Server) refreshKEV() error {
	path := filepath.Join(s.vulnDir(), "kev.json")
	s.vdb.mu.RLock()
	have := !s.vdb.kevTime.IsZero()
	s.vdb.mu.RUnlock()
	fi, statErr := os.Stat(path)
	var raw []byte
	var when time.Time
	if statErr == nil && time.Since(fi.ModTime()) < 24*time.Hour {
		if have {
			return nil
		}
		raw, _ = os.ReadFile(path)
		when = fi.ModTime()
	} else {
		var buf bytes.Buffer
		if err := vulnGet(&http.Client{Timeout: 2 * time.Minute}, kevURL, 64<<20, &buf); err != nil {
			if !have && statErr == nil {
				raw, _ = os.ReadFile(path)
				when = fi.ModTime()
			}
			if raw == nil {
				return err
			}
		} else {
			raw = buf.Bytes()
			when = time.Now().UTC()
			writeAtomic(path, raw)
		}
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	kev := map[string]bool{}
	for _, v := range doc.Vulnerabilities {
		kev[v.CVE] = true
	}
	if len(kev) == 0 {
		return fmt.Errorf("KEV catalogue is empty")
	}
	s.vdb.mu.Lock()
	s.vdb.kev, s.vdb.kevTime = kev, when
	s.vdb.mu.Unlock()
	return nil
}

func (s *Server) setVulnErr(k string, err error) {
	s.vdb.mu.Lock()
	defer s.vdb.mu.Unlock()
	if s.vdb.errs == nil {
		s.vdb.errs = map[string]string{}
	}
	if err != nil {
		s.vdb.errs[k] = err.Error()
		log.Printf("vuln %s: %v", k, err)
	} else {
		delete(s.vdb.errs, k)
	}
}

// setIndex keeps a complete index, reduced to the installed packages.
// Caller does not hold s.mu.
func (s *Server) setIndex(vi *vulnIndex) {
	if vi.kept == nil {
		s.mu.Lock()
		names := s.installedNames(vi.Release)
		s.mu.Unlock()
		vi = vi.prune(names)
	}
	s.vdb.mu.Lock()
	if s.vdb.idx == nil {
		s.vdb.idx = map[string]*vulnIndex{}
	}
	s.vdb.idx[vi.Release] = vi
	s.vdb.mu.Unlock()
}

// refreshVulns brings the data for every release in use up to date and
// matches all hosts again. Runs in its own goroutine, one at a time.
func (s *Server) refreshVulns() {
	if !s.cfg.VulnLookup {
		return
	}
	s.vdb.again.Store(true)
	for s.vdb.again.Load() && s.vdb.running.CompareAndSwap(false, true) {
		s.vdb.again.Store(false)
		s.refreshVulnsOnce()
		s.vdb.running.Store(false)
	}
}

func (s *Server) refreshVulnsOnce() {
	os.MkdirAll(s.vulnDir(), 0o700)
	s.setVulnErr("kev", s.refreshKEV())

	s.mu.Lock()
	need := map[string]bool{}
	for _, p := range s.pkgs {
		if p.Eco != "" {
			need[p.Eco] = true
		}
	}
	s.mu.Unlock()

	// Current index per release, from memory or disk; due ones are fetched.
	due := map[string]*vulnIndex{}
	for rel := range need {
		s.vdb.mu.RLock()
		vi := s.vdb.idx[rel]
		s.vdb.mu.RUnlock()
		if vi == nil {
			if vi = s.loadIndex(rel); vi != nil {
				s.setIndex(vi)
			}
		}
		if vi == nil || time.Since(vi.Updated) > vulnRefresh {
			due[rel] = vi
		}
	}
	var debian []string
	for rel, old := range due {
		dist, code, _ := strings.Cut(rel, ":")
		if dist == "debian" {
			debian = append(debian, code)
			continue
		}
		var since time.Time
		if old != nil {
			since = old.Source
		}
		f, lm, err := s.vulnFetch(fmt.Sprintf(ubuntuOVAL, code), since)
		if err == nil && f == nil {
			s.touchIndex(rel) // unchanged
		} else if err == nil {
			var vi *vulnIndex
			vi, err = parseOVAL(bzip2.NewReader(f), rel)
			f.Close()
			if err == nil {
				vi.Updated, vi.Source = time.Now().UTC(), lm
				vi.build()
				s.saveIndex(vi)
				s.setIndex(vi)
			}
		}
		s.setVulnErr(rel, err)
	}
	if len(debian) > 0 {
		since := time.Now()
		for _, c := range debian {
			if old := due["debian:"+c]; old == nil {
				since = time.Time{}
			} else if !since.IsZero() && old.Source.Before(since) {
				since = old.Source
			}
		}
		f, lm, err := s.vulnFetch(debianJSON, since)
		if err == nil && f == nil {
			for _, c := range debian {
				s.touchIndex("debian:" + c)
			}
		} else if err == nil {
			want := map[string]bool{}
			for _, c := range debian {
				want[c] = true
			}
			var r io.Reader = f
			var all map[string]*vulnIndex
			if zr, gerr := gzip.NewReader(f); gerr == nil {
				r = zr
			} else {
				f.Seek(0, io.SeekStart)
			}
			all, err = parseDebian(r, want)
			f.Close()
			for _, vi := range all {
				vi.Updated, vi.Source = time.Now().UTC(), lm
				vi.build()
				s.saveIndex(vi)
				s.setIndex(vi)
			}
		}
		s.setVulnErr("debian", err)
	}
	s.refreshOSV()
	// The KEV catalogue changes without the indexes changing, so every
	// refresh matches again; only conditions that are new alert.
	s.matchAll()
}

// touchIndex marks the complete index on disk as current.
func (s *Server) touchIndex(rel string) {
	if full := s.loadIndex(rel); full != nil {
		full.Updated = time.Now().UTC()
		s.saveIndex(full)
		s.setIndex(full)
	}
}

// matchAll matches every host whose packages are known.
func (s *Server) matchAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []*Alert
	for id, p := range s.pkgs {
		a := s.state.Agents[id]
		if a == nil {
			continue
		}
		fresh = append(fresh, s.raise(s.matchAgent(a, p), a.ID, 0)...)
	}
	for id, inv := range s.apps {
		if a := s.state.Agents[id]; a != nil {
			fresh = append(fresh, s.raise(s.matchApps(a, inv), a.ID, 0)...)
		}
	}
	s.saveLocked()
	s.notifyAlerts(fresh)
}

// matchAgent compares one host's packages with the index of its release.
// Caller holds s.mu.
func (s *Server) matchAgent(a *AgentRec, p *agentPackages) []finding {
	sum := &VulnSummary{Ecosystem: p.Eco, Checked: time.Now().UTC(), Packages: len(p.List), Fixable: map[string]int{}, Unfixed: map[string]int{}}
	if p.Eco == "" {
		sum.Error = "unsupported: " + p.OS
		a.Vulns = sum
		return nil
	}
	s.vdb.mu.RLock()
	vi := s.vdb.idx[p.Eco]
	kev := s.vdb.kev
	s.vdb.mu.RUnlock()
	if vi == nil {
		sum.Error = "no vulnerability data for " + p.Eco + " yet"
		a.Vulns = sum
		return nil
	}
	var hits []VulnHit
	for _, pk := range p.List {
		name, ver := pk[0], pk[1]
		seen := map[string]bool{}
		for _, r := range vi.byPkg[name] {
			for _, vp := range r.Pkgs {
				if vp.Name != name || seen[r.CVE] {
					continue
				}
				if vp.Fixed != "" && dpkgver.Compare(ver, vp.Fixed) >= 0 {
					continue
				}
				seen[r.CVE] = true
				hits = append(hits, VulnHit{CVE: r.CVE, Package: name, Installed: ver, Fixed: vp.Fixed, Severity: vp.Severity, Pro: vp.Pro, KEV: kev[r.CVE]})
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].KEV != hits[j].KEV {
			return hits[i].KEV
		}
		if so := severityOrder[hits[i].Severity] - severityOrder[hits[j].Severity]; so != 0 {
			return so > 0
		}
		return hits[i].CVE > hits[j].CVE
	})
	var conds []condition
	severe := map[string][]VulnHit{}
	exploited := map[string][]VulnHit{}
	for _, h := range hits {
		fixable := h.Fixed != "" && !h.Pro
		if fixable {
			sum.Fixable[h.Severity]++
			if len(sum.Top) < 100 {
				sum.Top = append(sum.Top, h)
			}
		} else {
			sum.Unfixed[h.Severity]++
		}
		if h.KEV {
			if len(sum.Exploited) < 50 {
				sum.Exploited = append(sum.Exploited, h)
			}
			if fixable {
				exploited[h.Package] = append(exploited[h.Package], h)
			}
		}
		if fixable && (h.Severity == "high" || h.Severity == "critical") {
			severe[h.Package] = append(severe[h.Package], h)
		}
	}
	// One alert per package: a kernel several releases behind has hundreds.
	perPackage := func(rule string, m map[string][]VulnHit) {
		for pkg, list := range m {
			var cves []string
			fixed := ""
			for i, h := range list {
				if i < 5 {
					cves = append(cves, h.CVE)
				} else if i == 5 {
					cves = append(cves, "…")
				}
				if fixed == "" || dpkgver.Compare(h.Fixed, fixed) > 0 {
					fixed = h.Fixed
				}
			}
			conds = append(conds, condition{rule, pkg, map[string]string{"package": pkg, "installed": list[0].Installed,
				"fixed": fixed, "count": fmt.Sprint(len(list)), "cves": strings.Join(cves, ", ")}})
		}
	}
	perPackage("vuln.exploited", exploited)
	perPackage("vuln.severe", severe)
	sort.Slice(conds, func(i, j int) bool { return conds[i].rule+conds[i].key < conds[j].rule+conds[j].key })
	a.Vulns = sum
	return s.conditionFindings(a, "vuln", conds)
}

func (s *Server) packagesPath(agentID string) string {
	return filepath.Join(s.vulnDir(), "packages-"+agentID+".json")
}

// packagesReceived stores a host's package list and matches it when the
// data for its release is loaded. Caller holds s.mu.
func (s *Server) packagesReceived(a *AgentRec, d map[string]any) []finding {
	list, _ := d["packages"].([]any)
	p := &agentPackages{OS: clip(str(d, "os_id")+" "+str(d, "os_version"), 60), Eco: releaseKey(str(d, "os_id"), str(d, "os_version"), str(d, "os_codename")), Received: time.Now().UTC()}
	for _, x := range list {
		pair, _ := x.([]any)
		if len(pair) != 2 || len(p.List) >= 20000 {
			continue
		}
		n, _ := pair[0].(string)
		v, _ := pair[1].(string)
		if n != "" && v != "" && len(n) < 200 && len(v) < 200 {
			p.List = append(p.List, [2]string{n, v})
		}
	}
	if s.pkgs == nil {
		s.pkgs = map[string]*agentPackages{}
	}
	s.pkgs[a.ID] = p
	if !s.cfg.VulnLookup {
		return nil
	}
	os.MkdirAll(s.vulnDir(), 0o700)
	if raw, err := json.Marshal(p); err == nil {
		writeAtomic(s.packagesPath(a.ID), raw)
	}
	s.vdb.mu.RLock()
	vi := s.vdb.idx[p.Eco]
	s.vdb.mu.RUnlock()
	if vi == nil && p.Eco != "" {
		go s.refreshVulns()
	}
	// A package no host had before: its data was left out of memory.
	if vi != nil && vi.kept != nil {
		for _, kv := range p.List {
			if !vi.kept[kv[0]] {
				if full := s.loadIndex(p.Eco); full != nil {
					reduced := full.prune(s.installedNames(p.Eco))
					s.vdb.mu.Lock()
					s.vdb.idx[p.Eco] = reduced
					s.vdb.mu.Unlock()
				}
				break
			}
		}
	}
	return s.matchAgent(a, p)
}

// loadPackages reads the stored package lists at start.
func (s *Server) loadPackages() {
	if !s.cfg.VulnLookup {
		return
	}
	files, _ := filepath.Glob(filepath.Join(s.vulnDir(), "packages-*.json"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pkgs == nil {
		s.pkgs = map[string]*agentPackages{}
	}
	for _, f := range files {
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "packages-"), ".json")
		if s.state.Agents[id] == nil {
			os.Remove(f)
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var p agentPackages
		if json.Unmarshal(raw, &p) == nil {
			s.pkgs[id] = &p
		}
	}
}

type vulnStatus struct {
	Enabled    bool              `json:"enabled"`
	Ecosystems []map[string]any  `json:"releases"`
	KEV        int               `json:"kev"`
	KEVTime    time.Time         `json:"kev_updated,omitempty"`
	Errors     map[string]string `json:"errors,omitempty"`
}

func (s *Server) vulnStatus() vulnStatus {
	s.vdb.mu.RLock()
	defer s.vdb.mu.RUnlock()
	st := vulnStatus{Enabled: s.cfg.VulnLookup, KEV: len(s.vdb.kev), KEVTime: s.vdb.kevTime, Errors: map[string]string{}, Ecosystems: []map[string]any{}}
	for k, v := range s.vdb.errs {
		st.Errors[k] = v
	}
	for eco, vi := range s.vdb.idx {
		st.Ecosystems = append(st.Ecosystems, map[string]any{"release": eco, "cves": len(vi.Recs), "updated": vi.Updated, "source": vi.Source})
	}
	st.Ecosystems = append(st.Ecosystems, s.osvStatus()...)
	sort.Slice(st.Ecosystems, func(i, j int) bool {
		return fmt.Sprint(st.Ecosystems[i]["release"]) < fmt.Sprint(st.Ecosystems[j]["release"])
	})
	return st
}

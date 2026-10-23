package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/osv"
)

// Application dependencies (vuln_lookup). Agents send the packages named in
// their lock files; the server matches them against OSV.dev data for npm,
// PyPI and Go modules. The data is OSV's public dump per ecosystem, read
// as a stream into a compact index once a week and brought up to date
// record by record from the ecosystem's modified_id.csv in between. Only
// ecosystems some host uses are fetched, and no package name leaves the
// server.

// osvBase is where OSV publishes its dumps (a variable for the tests).
var osvBase = "https://osv-vulnerabilities.storage.googleapis.com/"

const (
	osvRebuild   = 7 * 24 * time.Hour
	osvSync      = 3 * time.Hour
	osvMaxZip    = 1 << 30
	osvMaxChange = 5000 // more changed records than this: build anew
)

type appPackage struct {
	Eco     string `json:"e"`
	Name    string `json:"n"`
	Version string `json:"v"`
	M       int    `json:"m"` // index of the first manifest naming it
}

type appManifest struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

type appInventory struct {
	Received  time.Time     `json:"received"`
	Manifests []appManifest `json:"manifests"`
	Packages  []appPackage  `json:"packages"`
	Truncated bool          `json:"truncated,omitempty"`
}

type AppHit struct {
	ID        string   `json:"id"`
	CVEs      []string `json:"cves,omitempty"`
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Installed string   `json:"installed"`
	Fixed     string   `json:"fixed,omitempty"`
	Severity  string   `json:"severity"`
	Malicious bool     `json:"malicious,omitempty"`
	KEV       bool     `json:"kev,omitempty"`
	Path      string   `json:"path"`
	Summary   string   `json:"summary,omitempty"`
}

type AppVulnSummary struct {
	Checked   time.Time      `json:"checked"`
	Manifests int            `json:"manifests"`
	Packages  int            `json:"packages"`
	Truncated bool           `json:"truncated,omitempty"`
	Counts    map[string]int `json:"counts"` // by severity, "unknown" for none given
	Malicious []AppHit       `json:"malicious,omitempty"`
	Top       []AppHit       `json:"top,omitempty"`
	Missing   []string       `json:"missing,omitempty"` // ecosystems without data yet
}

type osvMeta struct {
	Built   time.Time `json:"built"`
	Synced  time.Time `json:"synced"`  // newest modified time applied
	Checked time.Time `json:"checked"` // last successful sync
	Lines   int       `json:"lines"`
}

type osvDB struct {
	mu   sync.RWMutex
	idx  map[string]map[string][]*osv.Entry // eco -> installed name -> entries
	kept map[string]map[string]bool
	meta map[string]osvMeta
}

func (s *Server) appsPath(agentID string) string {
	return filepath.Join(s.vulnDir(), "apps-"+agentID+".json")
}

func (s *Server) osvPath(eco, ext string) string {
	return filepath.Join(s.vulnDir(), "osv-"+eco+"."+ext)
}

// appsReceived stores a host's application packages and matches them.
// Caller holds s.mu.
func (s *Server) appsReceived(a *AgentRec, d map[string]any) []finding {
	inv := &appInventory{Received: time.Now().UTC(), Truncated: d["truncated"] == true}
	ms, _ := d["manifests"].([]any)
	for _, x := range ms {
		m, _ := x.([]any)
		if len(m) != 2 || len(inv.Manifests) >= 1000 {
			continue
		}
		p, _ := m[0].(string)
		n, _ := m[1].(float64)
		inv.Manifests = append(inv.Manifests, appManifest{Path: clip(p, 300), Count: int(n)})
	}
	eco := map[string]bool{}
	for _, e := range osv.Ecosystems {
		eco[e] = true
	}
	pk, _ := d["packages"].([]any)
	for _, x := range pk {
		p, _ := x.([]any)
		if len(p) != 4 || len(inv.Packages) >= 20000 {
			continue
		}
		e, _ := p[0].(string)
		n, _ := p[1].(string)
		v, _ := p[2].(string)
		m, _ := p[3].(float64)
		if eco[e] && n != "" && v != "" && len(n) < 214 && len(v) < 100 && int(m) >= 0 && int(m) < len(inv.Manifests) {
			inv.Packages = append(inv.Packages, appPackage{e, osv.NormalizeName(e, n), v, int(m)})
		}
	}
	if s.apps == nil {
		s.apps = map[string]*appInventory{}
	}
	s.apps[a.ID] = inv
	if !s.cfg.VulnLookup {
		return nil
	}
	os.MkdirAll(s.vulnDir(), 0o700)
	if raw, err := json.Marshal(inv); err == nil {
		writeAtomic(s.appsPath(a.ID), raw)
	}
	// Data missing, or a name no host had before (left out of memory):
	// the refresh loads it and matches again.
	s.odb.mu.RLock()
	stale := false
	for _, p := range inv.Packages {
		if k := s.odb.kept[p.Eco]; k == nil || !k[p.Name] {
			stale = true
			break
		}
	}
	s.odb.mu.RUnlock()
	if stale {
		go s.refreshVulns()
	}
	return s.matchApps(a, inv)
}

// loadApps reads the stored inventories at start. Caller does not hold s.mu.
func (s *Server) loadApps() {
	if !s.cfg.VulnLookup {
		return
	}
	files, _ := filepath.Glob(filepath.Join(s.vulnDir(), "apps-*.json"))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.apps == nil {
		s.apps = map[string]*appInventory{}
	}
	for _, f := range files {
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "apps-"), ".json")
		if s.state.Agents[id] == nil {
			os.Remove(f)
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var inv appInventory
		if json.Unmarshal(raw, &inv) == nil {
			s.apps[id] = &inv
		}
	}
}

// appNames are the package names in use per ecosystem. Caller holds s.mu.
func (s *Server) appNames() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, inv := range s.apps {
		for _, p := range inv.Packages {
			if out[p.Eco] == nil {
				out[p.Eco] = map[string]bool{}
			}
			out[p.Eco][p.Name] = true
		}
	}
	return out
}

// refreshOSV brings the data of every ecosystem in use up to date and
// loads it for the names in use. Part of refreshVulnsOnce.
func (s *Server) refreshOSV() {
	s.mu.Lock()
	names := s.appNames()
	s.mu.Unlock()
	for _, eco := range osv.Ecosystems {
		if len(names[eco]) == 0 {
			continue
		}
		meta := s.loadOSVMeta(eco)
		var err error
		switch {
		case meta.Built.IsZero() || time.Since(meta.Built) > osvRebuild:
			meta, err = s.buildOSV(eco)
		case time.Since(meta.Checked) > osvSync:
			meta, err = s.syncOSV(eco, meta)
		}
		s.setVulnErr("osv:"+eco, err)
		if meta.Built.IsZero() {
			continue
		}
		f, ferr := os.Open(s.osvPath(eco, "idx.gz"))
		if ferr != nil {
			s.setVulnErr("osv:"+eco, ferr)
			continue
		}
		ov := s.loadOverlay(eco)
		idx, serr := osv.Scan(f, ov, names[eco])
		f.Close()
		if serr != nil {
			s.setVulnErr("osv:"+eco, serr)
			continue
		}
		s.odb.mu.Lock()
		if s.odb.idx == nil {
			s.odb.idx, s.odb.kept, s.odb.meta = map[string]map[string][]*osv.Entry{}, map[string]map[string]bool{}, map[string]osvMeta{}
		}
		s.odb.idx[eco], s.odb.kept[eco], s.odb.meta[eco] = idx, names[eco], meta
		s.odb.mu.Unlock()
	}
}

func (s *Server) loadOSVMeta(eco string) osvMeta {
	var m osvMeta
	if raw, err := os.ReadFile(s.osvPath(eco, "meta.json")); err == nil {
		json.Unmarshal(raw, &m)
	}
	if _, err := os.Stat(s.osvPath(eco, "idx.gz")); err != nil {
		return osvMeta{}
	}
	return m
}

func (s *Server) loadOverlay(eco string) *osv.Overlay {
	ov := &osv.Overlay{Records: map[string]map[string]*osv.Entry{}}
	if raw, err := os.ReadFile(s.osvPath(eco, "overlay.json")); err == nil {
		json.Unmarshal(raw, ov)
	}
	if ov.Records == nil {
		ov.Records = map[string]map[string]*osv.Entry{}
	}
	return ov
}

func osvGet(c *http.Client, u string, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vigil/"+Version+" (+https://github.com/akquisio-dev/vigil)")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusPartialContent {
		res.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", u, res.StatusCode)
	}
	return res, nil
}

// buildOSV reads the ecosystem's dump as it downloads into a new index.
// The overlay starts empty. The dump is a snapshot of some hours ago, so
// the next sync fetches what changed since its newest record (with an hour
// to spare; a record fetched twice replaces itself).
func (s *Server) buildOSV(eco string) (osvMeta, error) {
	start := time.Now().UTC()
	res, err := osvGet(&http.Client{Timeout: 30 * time.Minute}, osvBase+eco+"/all.zip", nil)
	if err != nil {
		return s.loadOSVMeta(eco), err
	}
	defer res.Body.Close()
	tmp, err := os.CreateTemp(s.vulnDir(), ".osv-*")
	if err != nil {
		return s.loadOSVMeta(eco), err
	}
	defer os.Remove(tmp.Name())
	n, newest, err := osv.BuildIndex(io.LimitReader(res.Body, osvMaxZip), eco, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return s.loadOSVMeta(eco), fmt.Errorf("%s dump: %w", eco, err)
	}
	if err := os.Rename(tmp.Name(), s.osvPath(eco, "idx.gz")); err != nil {
		return s.loadOSVMeta(eco), err
	}
	os.Remove(s.osvPath(eco, "overlay.json"))
	if newest.IsZero() || newest.After(start) {
		newest = start.Add(-48 * time.Hour)
	}
	m := osvMeta{Built: start, Synced: newest.Add(-time.Hour), Checked: start, Lines: n}
	raw, _ := json.Marshal(m)
	return m, writeAtomic(s.osvPath(eco, "meta.json"), raw)
}

// syncOSV applies the records changed since the last sync. modified_id.csv
// lists every record, newest first, so only its head is read.
func (s *Server) syncOSV(eco string, meta osvMeta) (osvMeta, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	var ids []string
	var newest time.Time
	for size := int64(256 << 10); ; size *= 4 {
		if size > 64<<20 {
			return s.buildOSV(eco)
		}
		res, err := osvGet(c, osvBase+eco+"/modified_id.csv", map[string]string{"Range": "bytes=0-" + strconv.FormatInt(size-1, 10)})
		if err != nil {
			return meta, err
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, size+1))
		res.Body.Close()
		if err != nil {
			return meta, err
		}
		// A 206 names the full length; a server that ignores Range sends
		// it all, cut here at size+1.
		whole := int64(len(b)) <= size
		if res.StatusCode == http.StatusPartialContent {
			_, total, _ := strings.Cut(res.Header.Get("Content-Range"), "/")
			n, err := strconv.ParseInt(total, 10, 64)
			whole = err == nil && n <= size
		}
		if !whole {
			b = b[:strings.LastIndexByte(string(b), '\n')+1] // a cut last line
		}
		var complete bool
		ids, newest, complete = osv.Changed(strings.NewReader(string(b)), meta.Synced)
		if complete || whole {
			break
		}
	}
	if len(ids) > osvMaxChange {
		return s.buildOSV(eco)
	}
	if len(ids) == 0 {
		meta.Checked = time.Now().UTC()
		raw, _ := json.Marshal(meta)
		return meta, writeAtomic(s.osvPath(eco, "meta.json"), raw)
	}
	ov := s.loadOverlay(eco)
	for _, id := range ids {
		if strings.ContainsAny(id, "/\\") || id == "" {
			continue
		}
		res, err := osvGet(c, osvBase+eco+"/"+id+".json", nil)
		if err != nil {
			return meta, err // Synced stays, the next sync tries again
		}
		raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		if err != nil {
			return meta, err
		}
		_, entries, _, err := osv.Parse(raw, eco)
		if err != nil {
			continue
		}
		if entries == nil {
			entries = map[string]*osv.Entry{}
		}
		ov.Records[id] = entries
	}
	ov.Synced = newest
	raw, _ := json.Marshal(ov)
	if err := writeAtomic(s.osvPath(eco, "overlay.json"), raw); err != nil {
		return meta, err
	}
	meta.Synced, meta.Checked = newest, time.Now().UTC()
	raw, _ = json.Marshal(meta)
	return meta, writeAtomic(s.osvPath(eco, "meta.json"), raw)
}

// matchApps compares one host's application packages with the OSV data.
// Caller holds s.mu.
func (s *Server) matchApps(a *AgentRec, inv *appInventory) []finding {
	sum := &AppVulnSummary{Checked: time.Now().UTC(), Manifests: len(inv.Manifests), Packages: len(inv.Packages), Truncated: inv.Truncated, Counts: map[string]int{}}
	// refreshOSV replaces the inner maps but never changes one.
	s.odb.mu.RLock()
	idx := make(map[string]map[string][]*osv.Entry, len(s.odb.idx))
	for k, v := range s.odb.idx {
		idx[k] = v
	}
	s.odb.mu.RUnlock()
	s.vdb.mu.RLock()
	kev := s.vdb.kev
	s.vdb.mu.RUnlock()

	missing := map[string]bool{}
	var hits []AppHit
	for _, p := range inv.Packages {
		byName, ok := idx[p.Eco]
		if !ok {
			missing[p.Eco] = true
			continue
		}
		entries := append([]*osv.Entry{}, byName[p.Name]...)
		// The same flaw comes as GHSA, PYSEC and GO records; the one that
		// names a severity counts.
		sort.SliceStable(entries, func(i, j int) bool { return osv.Score(entries[i]) > osv.Score(entries[j]) })
		seen := map[string]bool{}
		for _, e := range entries {
			if seen[e.ID] || !e.Affects(p.Eco, p.Version) {
				continue
			}
			dup := false
			for _, id := range e.Aliases {
				dup = dup || seen[id]
			}
			seen[e.ID] = true
			for _, id := range e.Aliases {
				seen[id] = true
			}
			if dup {
				continue
			}
			h := AppHit{ID: e.ID, CVEs: e.CVEs(), Ecosystem: p.Eco, Package: p.Name, Installed: p.Version, Fixed: e.FixedAfter(p.Eco, p.Version),
				Severity: e.Severity, Malicious: e.Malicious(), Path: inv.Manifests[p.M].Path, Summary: e.Summary}
			for _, c := range h.CVEs {
				h.KEV = h.KEV || kev[c]
			}
			hits = append(hits, h)
		}
	}
	for e := range missing {
		sum.Missing = append(sum.Missing, e)
	}
	sort.Strings(sum.Missing)
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Malicious != hits[j].Malicious {
			return hits[i].Malicious
		}
		if hits[i].KEV != hits[j].KEV {
			return hits[i].KEV
		}
		if so := severityOrder[hits[i].Severity] - severityOrder[hits[j].Severity]; so != 0 {
			return so > 0
		}
		return hits[i].ID > hits[j].ID
	})

	type group struct {
		hits []AppHit
	}
	malicious, exploited, severe := map[string]*group{}, map[string]*group{}, map[string]*group{}
	// malicious packages one by one; known flaws per lock file, which is
	// what gets updated in one go
	add := func(m map[string]*group, h AppHit) {
		k := h.Ecosystem + "|" + h.Path
		if h.Malicious {
			k = h.Ecosystem + "|" + h.Package + "|" + h.Installed
		}
		if m[k] == nil {
			m[k] = &group{}
		}
		m[k].hits = append(m[k].hits, h)
	}
	for _, h := range hits {
		sev := h.Severity
		if sev == "" {
			sev = "unknown"
		}
		sum.Counts[sev]++
		switch {
		case h.Malicious:
			sum.Malicious = append(sum.Malicious, h)
			add(malicious, h)
			continue
		case len(sum.Top) < 100:
			sum.Top = append(sum.Top, h)
		}
		if h.Fixed == "" {
			continue
		}
		if h.KEV {
			add(exploited, h)
		} else if h.Severity == "high" || h.Severity == "critical" {
			add(severe, h)
		}
	}
	var conds []condition
	perGroup := func(rule string, m map[string]*group) {
		for k, g := range m {
			var ids []string
			type pv struct{ name, installed, fixed string }
			var pkgs []*pv
			byName := map[string]*pv{}
			for i, h := range g.hits {
				id := h.ID
				if len(h.CVEs) > 0 {
					id = h.CVEs[0]
				}
				if i < 5 {
					ids = append(ids, id)
				} else if i == 5 {
					ids = append(ids, "…")
				}
				p := byName[h.Package+"|"+h.Installed]
				if p == nil {
					p = &pv{name: h.Package, installed: h.Installed}
					byName[h.Package+"|"+h.Installed] = p
					pkgs = append(pkgs, p)
				}
				// the highest fixed version covers all of the package's flaws
				if c, ok := osv.Compare(h.Ecosystem, h.Fixed, p.fixed); h.Fixed != "" && (p.fixed == "" || (ok && c > 0)) {
					p.fixed = h.Fixed
				}
			}
			var list []string
			for i, p := range pkgs {
				if i == 4 {
					list = append(list, fmt.Sprintf("%d more", len(pkgs)-4))
					break
				}
				list = append(list, p.name+" "+p.installed+" (fixed in "+p.fixed+")")
			}
			h := g.hits[0]
			params := map[string]string{"ecosystem": h.Ecosystem, "path": h.Path, "count": fmt.Sprint(len(g.hits)),
				"ids": strings.Join(ids, ", "), "packages": strings.Join(list, ", "), "package_count": fmt.Sprint(len(pkgs))}
			if rule == "vuln.app_malicious" || len(pkgs) == 1 {
				params["package"], params["installed"], params["fixed"] = h.Package, h.Installed, pkgs[0].fixed
			}
			conds = append(conds, condition{rule, k, params})
		}
	}
	perGroup("vuln.app_malicious", malicious)
	perGroup("vuln.app_exploited", exploited)
	perGroup("vuln.app_severe", severe)
	sort.Slice(conds, func(i, j int) bool { return conds[i].rule+conds[i].key < conds[j].rule+conds[j].key })
	a.AppVulns = sum
	// An ecosystem without data (a failed download) keeps its open
	// conditions until its data is back.
	for full := range a.Conditions["apps"] {
		rule, rest, _ := strings.Cut(full, "|")
		_, key, _ := strings.Cut(rest, "|")
		if eco, _, _ := strings.Cut(key, "|"); missing[eco] {
			conds = append(conds, condition{rule, key, nil})
		}
	}
	return s.conditionFindings(a, "apps", conds)
}

func (s *Server) osvStatus() []map[string]any {
	s.odb.mu.RLock()
	defer s.odb.mu.RUnlock()
	out := []map[string]any{}
	for _, eco := range osv.Ecosystems {
		m, ok := s.odb.meta[eco]
		if !ok {
			continue
		}
		out = append(out, map[string]any{"release": "osv:" + eco, "cves": m.Lines, "updated": m.Checked, "source": m.Built})
	}
	return out
}

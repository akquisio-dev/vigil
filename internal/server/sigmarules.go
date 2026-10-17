package server

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/sigma"
)

// Sigma rules (sigma_dir): the Linux rules of the Sigma format, matched
// against the events vigil has for their log source. vigil does not see
// every program start, only the suspicious ones, the ones typed in SSH
// sessions and new ones; process_creation rules therefore apply to those.

type sigmaSource struct {
	types  []string
	fields map[string]string // Sigma field -> event field
}

var sigmaSources = map[string]sigmaSource{
	"process_creation": {
		types: []string{"process.exec", "session.exec", "process.rare", "process.rare_child"},
		fields: map[string]string{"Image": "exe", "CommandLine": "cmdline", "ParentImage": "parent_exe", "CurrentDirectory": "cwd",
			"ProcessId": "pid", "ParentProcessId": "ppid", "User": "user", "OriginalFileName": "exe"},
	},
	"network_connection": {
		types:  []string{"net.connection"},
		fields: map[string]string{"DestinationIp": "remote_ip", "DestinationPort": "remote_port", "Image": "exe", "Initiated": "initiated", "User": "user"},
	},
	"file_event": {
		types:  []string{"file.added", "file.changed"},
		fields: map[string]string{"TargetFilename": "path"},
	},
	"file_change": {
		types:  []string{"file.changed"},
		fields: map[string]string{"TargetFilename": "path"},
	},
	"file_delete": {
		types:  []string{"file.removed"},
		fields: map[string]string{"TargetFilename": "path"},
	},
}

type sigmaRule struct {
	*sigma.Rule
	id   string
	file string
	src  sigmaSource
	sev  string
	tech string
}

var (
	sigmaMu      sync.RWMutex
	sigmaByID    = map[string]*sigmaRule{}
	sigmaByType  = map[string][]*sigmaRule{}
	sigmaErrs    []string
	sigmaSkipped int
	sigmaStamp   map[string]time.Time
)

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func sigmaID(r *sigma.Rule) string {
	slug := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(r.Title), "_"), "_")
	if len(slug) > 44 {
		slug = slug[:44]
	}
	if id := strings.ToLower(r.ID); len(id) >= 8 {
		return "sigma." + slug + "." + slugRe.ReplaceAllString(id[:8], "")
	}
	return "sigma." + slug
}

var techTag = regexp.MustCompile(`^attack\.(t\d{4}(\.\d{3})?)$`)

// LoadSigma reads sigma_dir (with subdirectories). It returns the number of
// active rules and the errors.
func LoadSigma(dir string) (int, []string) {
	if dir == "" {
		return 0, nil
	}
	var files []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	stamp := map[string]time.Time{}
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil {
			stamp[f] = fi.ModTime()
		}
	}
	sigmaMu.RLock()
	same := sigmaStamp != nil && len(stamp) == len(sigmaStamp)
	for f, t := range stamp {
		if !sigmaStamp[f].Equal(t) {
			same = false
		}
	}
	n := len(sigmaByID)
	sigmaMu.RUnlock()
	if same {
		return n, nil
	}
	byID := map[string]*sigmaRule{}
	byType := map[string][]*sigmaRule{}
	var errs []string
	skipped := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil || len(b) > 1<<20 {
			errs = append(errs, filepath.Base(f)+": unreadable or larger than 1 MB")
			continue
		}
		rel, _ := filepath.Rel(dir, f)
		parsed, cerrs := sigma.ParseFile(string(b))
		for _, e := range cerrs {
			errs = append(errs, rel+": "+e.Error())
		}
		for _, r := range parsed {
			src, ok := sigmaSources[r.Category]
			if r.Product != "linux" && r.Product != "" || !ok || r.Service != "" {
				skipped++ // a log source vigil has no events for
				continue
			}
			unknown := ""
			for _, fld := range r.Fields {
				if _, ok := src.fields[fld]; !ok && fld != "" {
					unknown = fld
				}
			}
			if unknown != "" {
				errs = append(errs, rel+": "+r.Title+": field "+unknown+" is not in vigil's "+r.Category+" events")
				continue
			}
			sr := &sigmaRule{Rule: r, id: sigmaID(r), file: rel, src: src}
			sr.sev = map[string]string{"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}[r.Level]
			if sr.sev == "" {
				sr.sev = "medium"
			}
			for _, t := range r.Tags {
				if m := techTag.FindStringSubmatch(t); m != nil {
					sr.tech = strings.ToUpper(m[1])
					break
				}
			}
			if _, dup := byID[sr.id]; dup {
				errs = append(errs, rel+": "+r.Title+": defined twice")
				continue
			}
			if _, builtin := rules[sr.id]; builtin {
				continue
			}
			byID[sr.id] = sr
			for _, t := range src.types {
				byType[t] = append(byType[t], sr)
			}
		}
	}
	sigmaMu.Lock()
	sigmaByID, sigmaByType, sigmaErrs, sigmaSkipped, sigmaStamp = byID, byType, errs, skipped, stamp
	sigmaMu.Unlock()
	log.Printf("sigma: %d rules active, %d for other log sources, %d errors", len(byID), skipped, len(errs))
	return len(byID), errs
}

func sigmaLookup(id string) (ruleDef, bool) {
	sigmaMu.RLock()
	defer sigmaMu.RUnlock()
	r := sigmaByID[id]
	if r == nil {
		return ruleDef{}, false
	}
	t := "Sigma: " + r.Title + " ({subject})"
	return ruleDef{Severity: r.sev, Technique: r.tech, En: t, De: t}, true
}

func sigmaInfo() []RuleInfo {
	sigmaMu.RLock()
	defer sigmaMu.RUnlock()
	var out []RuleInfo
	for _, r := range sigmaByID {
		out = append(out, RuleInfo{ID: r.id, Severity: r.sev, Technique: r.tech, Title: "Sigma: " + r.Title, Trigger: r.Description, Custom: true, File: "sigma/" + r.file})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sigmaStatus() map[string]any {
	sigmaMu.RLock()
	defer sigmaMu.RUnlock()
	return map[string]any{"rules": len(sigmaByID), "other_sources": sigmaSkipped, "errors": append([]string{}, sigmaErrs...)}
}

func (s *Server) evaluateSigma(a *AgentRec, r *Record) []finding {
	sigmaMu.RLock()
	list := sigmaByType[r.Event.Type]
	sigmaMu.RUnlock()
	if len(list) == 0 {
		return nil
	}
	d := r.Event.Data
	var out []finding
	for _, sr := range list {
		get := func(f string) (string, bool) {
			k, ok := sr.src.fields[f]
			if !ok {
				return "", false
			}
			if f == "User" && str(d, "user") == "" {
				if uid, ok := d["uid"].(float64); ok && uid == 0 {
					return "root", true
				}
			}
			if f == "Initiated" {
				return "true", true // vigil reports outbound connections only
			}
			v, ok := d[k]
			if !ok || v == nil {
				return "", false
			}
			if n, isNum := v.(float64); isNum {
				return strconv.FormatFloat(n, 'f', -1, 64), true
			}
			return str(d, k), true
		}
		all := func() []string {
			var vs []string
			for _, k := range sr.src.fields {
				if v := str(d, k); v != "" {
					vs = append(vs, v)
				}
			}
			return vs
		}
		if !sr.Match(get, all) {
			continue
		}
		subject := str(d, "exe")
		if subject == "" {
			subject = str(d, "path")
		}
		if ip := str(d, "remote_ip"); ip != "" {
			subject += " → " + ip + ":" + str(d, "remote_port")
		}
		p := map[string]string{"subject": subject, "sigma_title": sr.Title, "sigma_id": sr.Rule.ID, "host": a.Name}
		for _, k := range []string{"exe", "cmdline", "path", "remote_ip", "remote_port", "user", "uid", "parent_exe", "pid"} {
			if v := str(d, k); v != "" {
				p[k] = v
			}
		}
		out = append(out, finding{Rule: sr.id, Key: sr.id + "|" + a.ID + "|" + subject, Params: p})
	}
	return out
}

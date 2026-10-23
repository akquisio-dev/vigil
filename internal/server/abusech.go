package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// abuse.ch retired its keyless downloads in October 2026: ThreatFox and
// MalwareBazaar answer 410 Gone without a key. Their exports now take a free
// Auth-Key (https://auth.abuse.ch/) in the URL path. The key is read from
// abusech_key_file on every refresh, so a new key needs no restart, and it is
// cut out of every error that could carry the URL into a log, the dashboard
// or an alert. Feodo Tracker still works without a key.

// Variables only so that tests can point them at a local server.
var (
	tfExport       = "https://threatfox-api.abuse.ch/v2/files/exports/%s/recent.json"
	mbExportRecent = "https://mb-api.abuse.ch/v2/files/exports/%s/recent.csv"
	mbExportFull   = "https://mb-api.abuse.ch/v2/files/exports/%s/full.csv.zip"
)

var (
	errNoAbuseKey = errors.New("needs an abuse.ch Auth-Key (abusech_key_file)")
	abuseKeyRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

func (s *Server) abuseKey() (string, error) {
	if s.cfg.AbuseCHKeyFile == "" {
		return "", errNoAbuseKey
	}
	b, err := os.ReadFile(s.cfg.AbuseCHKeyFile)
	if err != nil {
		return "", fmt.Errorf("abusech_key_file: %v", err)
	}
	k := strings.TrimSpace(string(b))
	if !abuseKeyRe.MatchString(k) {
		return "", errors.New("abusech_key_file does not hold an Auth-Key")
	}
	return k, nil
}

// abuseURL fills the key into an export URL template.
func (s *Server) abuseURL(tmpl string) (string, string, error) {
	k, err := s.abuseKey()
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf(tmpl, k), k, nil
}

// redactKey removes the key from a message (net/http errors quote the URL).
func redactKey(msg, key string) string {
	if key == "" {
		return msg
	}
	return strings.ReplaceAll(msg, key, "<key>")
}

// publicURL is how a list's address is shown: without the key.
func publicURL(tmpl string) string { return strings.ReplaceAll(tmpl, "%s", "<key>") }

// Last successful download per source, kept as the modification time of a
// marker file so that intel.stale survives restarts.
func (s *Server) intelOKFile(source string) string {
	return filepath.Join(s.cfg.DataDir, "intel", source+".ok")
}

func (s *Server) markIntelOK(source string, at time.Time) {
	p := s.intelOKFile(source)
	if err := os.WriteFile(p, nil, 0o600); err == nil {
		os.Chtimes(p, at, at)
	}
}

func (s *Server) intelOK(source string) time.Time {
	if fi, err := os.Stat(s.intelOKFile(source)); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

const intelStaleAfter = 48 * time.Hour

// intelSources are the downloads checked for staleness, with their last
// success and current error.
func (s *Server) intelSources() map[string][2]string {
	out := map[string][2]string{}
	if s.cfg.ThreatIntel {
		for _, st := range s.intel.status() {
			out[st.Name] = [2]string{st.Updated.Format(time.RFC3339), st.Error}
		}
	}
	if s.cfg.HashIntel {
		s.hashes.mu.RLock()
		errs := s.hashes.errs
		s.hashes.mu.RUnlock()
		for _, src := range []string{"malwarebazaar"} {
			out[src] = [2]string{s.intelOK(src).Format(time.RFC3339), errs[src]}
		}
	}
	return out
}

// checkIntelStale raises intel.stale for a source that has not been
// downloaded for two days, and resolves it once it is again. A new
// installation gets two days before the first complaint. A list that waits
// for an abuse.ch key nobody configured is not stale: that is a choice, and
// the dashboard says so. Caller holds s.mu.
func (s *Server) checkIntelStale(now time.Time, sources map[string][2]string) []*Alert {
	var fs []finding
	for name, v := range sources {
		key := "intel.stale|" + name
		if v[1] == errNoAbuseKey.Error() {
			s.resolveKey(key, "system")
			continue
		}
		last, _ := time.Parse(time.RFC3339, v[0])
		if !last.IsZero() && last.Year() > 1 && now.Sub(last) <= intelStaleAfter {
			s.resolveKey(key, "system")
			continue
		}
		if (last.IsZero() || last.Year() <= 1) && now.Sub(s.started) < intelStaleAfter {
			continue
		}
		age := "never"
		if last.Year() > 1 {
			age = fmtDuration(now.Sub(last))
		}
		reason := v[1]
		if reason == "" {
			reason = "no successful download"
		}
		fs = append(fs, finding{Rule: "intel.stale", Key: key, Params: map[string]string{"source": name, "age": age, "error": clip(reason, 200)}})
	}
	if len(fs) == 0 {
		return nil
	}
	return s.raise(fs, "", 0)
}

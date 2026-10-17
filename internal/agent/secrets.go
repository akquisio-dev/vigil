package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Exposed secrets: private keys, API tokens and credentials in files that
// every user on the host can read. A web application or service that gets
// taken over runs as its own user; what it can read decides how far the
// attacker gets. Directories that others cannot enter are not descended
// into, so secrets kept private (root's home, 0700 directories, 0600 files)
// are never read. The secret itself never leaves the host: events carry the
// path, the kind, the line and a short hash.

var secretRootsDefault = []string{"/etc", "/home", "/root", "/srv", "/opt", "/var/www", "/var/backups", "/var/lib", "/tmp", "/var/tmp"}

// Directories that hold vendored code and test fixtures full of sample keys.
var secretSkipNames = map[string]bool{"node_modules": true, "vendor": true, "site-packages": true, "dist-packages": true,
	"__pycache__": true, ".cache": true, ".npm": true, ".cargo": true, ".rustup": true, "go": true, "testdata": true,
	"fixtures": true, "test": true, "tests": true, "spec": true}

var secretSkipPaths = []string{"/etc/ssl/certs", "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/dpkg",
	"/var/lib/apt", "/var/lib/snapd", "/var/lib/lxd", "/var/lib/lxc", "/var/lib/mysql", "/var/lib/postgresql", "/var/lib/vigil-agent"}

const (
	secretMaxFile  = 512 << 10
	secretMaxFiles = 200000
	secretEvery    = 24 * time.Hour
)

type secretPattern struct {
	kind   string
	anchor []string // cheap prefilter; the regexp only runs when one is present
	re     *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"private_key", []string{"PRIVATE KEY-----"}, regexp.MustCompile(`-----BEGIN ((?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----`)},
	{"aws_key", []string{"AKIA", "ASIA"}, regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github_token", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"gitlab_token", []string{"glpat-"}, regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{"slack_token", []string{"xox"}, regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"stripe_key", []string{"sk_live_", "rk_live_"}, regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{20,}`)},
	{"google_api_key", []string{"AIza"}, regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"ai_api_key", []string{"sk-ant-", "sk-proj-"}, regexp.MustCompile(`\bsk-(?:ant-[A-Za-z0-9_-]{20,}|proj-[A-Za-z0-9_-]{20,})`)},
	{"url_credentials", []string{"://"}, regexp.MustCompile(`\b(?:https?|ftp|mysql|postgres(?:ql)?|redis|rediss|mongodb(?:\+srv)?|amqps?|smtps?)://([^/\s:@'"]+):([^/\s@'"]{4,})@[A-Za-z0-9.-]+`)},
}

var secretPlaceholders = []string{"password", "passwd", "pass", "secret", "changeme", "example", "xxxx", "****", "<", "${", "{{", "%s", "$(", "your", "token"}

func secretPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, p := range secretPlaceholders {
		if l == p || strings.HasPrefix(l, p) && len(l) <= len(p)+2 || strings.HasPrefix(l, "your") || strings.Contains(l, "${") || strings.Contains(l, "{{") || strings.HasPrefix(l, "<") {
			return true
		}
	}
	return false
}

// opensshEncrypted reads the cipher name of an OPENSSH PRIVATE KEY block.
func opensshEncrypted(block string) bool {
	body := block
	if i := strings.Index(body, "-----\n"); i >= 0 {
		body = body[i+6:]
	}
	if i := strings.Index(body, "-----END"); i >= 0 {
		body = body[:i]
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	const magic = "openssh-key-v1\x00"
	if err != nil || len(raw) < len(magic)+4 || string(raw[:len(magic)]) != magic {
		return false
	}
	n := binary.BigEndian.Uint32(raw[len(magic):])
	rest := raw[len(magic)+4:]
	if int(n) > len(rest) {
		return false
	}
	return string(rest[:n]) != "none"
}

type secretHit struct {
	Kind string
	Line int
	FP   string
}

// findSecrets scans one file's content. name is the base name, for the
// formats recognised by file name (.env, .pgpass, .netrc).
func findSecrets(name string, b []byte) []secretHit {
	var hits []secretHit
	seen := map[string]bool{}
	hit := func(kind string, off int, val []byte) {
		sum := sha256.Sum256(val)
		fp := hex.EncodeToString(sum[:6])
		if seen[kind+fp] || len(hits) >= 20 {
			return
		}
		seen[kind+fp] = true
		hits = append(hits, secretHit{Kind: kind, Line: bytes.Count(b[:off], []byte("\n")) + 1, FP: fp})
	}
	for _, p := range secretPatterns {
		found := false
		for _, a := range p.anchor {
			if bytes.Contains(b, []byte(a)) {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		for _, m := range p.re.FindAllSubmatchIndex(b, 50) {
			val := b[m[0]:m[1]]
			switch p.kind {
			case "private_key":
				// The block up to its END line, for the encryption check and the hash.
				end := bytes.Index(b[m[1]:], []byte("-----END"))
				if end < 0 || end > 16<<10 {
					continue
				}
				val = b[m[0] : m[1]+end]
				if m[2] >= 0 && string(b[m[2]:m[3]]) == "ENCRYPTED " || bytes.Contains(val, []byte("Proc-Type: 4,ENCRYPTED")) {
					continue
				}
				if m[2] >= 0 && string(b[m[2]:m[3]]) == "OPENSSH " && opensshEncrypted(string(val)) {
					continue
				}
			case "url_credentials":
				if secretPlaceholder(string(b[m[4]:m[5]])) {
					continue
				}
			}
			hit(p.kind, m[0], val)
		}
	}
	lname := strings.ToLower(name)
	switch {
	case lname == ".env" || strings.HasPrefix(lname, ".env.") || strings.HasSuffix(lname, ".env"):
		if strings.HasSuffix(lname, ".example") || strings.HasSuffix(lname, ".sample") || strings.HasSuffix(lname, ".template") || strings.HasSuffix(lname, ".dist") {
			break
		}
		off := 0
		for _, line := range bytes.SplitAfter(b, []byte("\n")) {
			l := strings.TrimSpace(string(line))
			l = strings.TrimPrefix(l, "export ")
			if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(k, "#") {
				uk := strings.ToUpper(strings.TrimSpace(k))
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				if v != "" && !secretPlaceholder(v) && len(v) >= 6 && (strings.Contains(uk, "PASS") || strings.Contains(uk, "SECRET") ||
					strings.Contains(uk, "TOKEN") || strings.HasSuffix(uk, "_KEY") || strings.Contains(uk, "PRIVATE")) {
					hit("env_secret", off, []byte(v))
				}
			}
			off += len(line)
		}
	case lname == ".pgpass":
		off := 0
		for _, line := range bytes.SplitAfter(b, []byte("\n")) {
			l := strings.TrimSpace(string(line))
			if f := strings.Split(l, ":"); len(f) >= 5 && !strings.HasPrefix(l, "#") && f[4] != "" {
				hit("pgpass", off, []byte(l))
			}
			off += len(line)
		}
	case lname == ".netrc" || lname == "_netrc":
		if i := bytes.Index(b, []byte("password")); i >= 0 {
			hit("netrc", i, b)
		}
	case lname == ".git-credentials":
		// the url_credentials pattern covers the content
	}
	return hits
}

// worldReachable reports whether every directory from / down to dir can be
// entered by any user.
func worldReachable(dir string) bool {
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm()&0o001 == 0 {
			return false
		}
		if d == "/" {
			return true
		}
	}
}

type secretFile struct {
	path string
	uid  uint32
	mode uint32
	hits []secretHit
}

// walkSecrets visits world-readable regular files below roots, entering only
// directories every user can enter, and stays on each root's filesystem.
func walkSecrets(ctx context.Context, roots []string, allMounts map[string]bool, skip map[string]bool) ([]secretFile, int, error) {
	var out []secretFile
	files := 0
	buf := make([]byte, secretMaxFile)
	var st syscall.Stat_t
	for _, root := range roots {
		if !worldReachable(root) {
			continue
		}
		stack := []string{root}
		for len(stack) > 0 {
			dir := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			f, err := os.Open(dir)
			if err != nil {
				continue
			}
			for {
				if ctx.Err() != nil {
					f.Close()
					return out, files, ctx.Err()
				}
				batch, err := f.ReadDir(256)
				for _, d := range batch {
					p := dir + "/" + d.Name()
					if syscall.Lstat(p, &st) != nil {
						continue
					}
					switch {
					case d.IsDir():
						if st.Mode&0o001 != 0 && !allMounts[p] && !secretSkipNames[d.Name()] && !underAny(p, secretSkipPaths) {
							if d.Name() == ".git" {
								// only the config, where remote URLs with tokens live
								if cfg := p + "/config"; worldReadableFile(cfg, &st) {
									out = scanSecretFile(out, cfg, &st, buf, skip)
								}
								continue
							}
							stack = append(stack, p)
						}
						continue
					case !d.Type().IsRegular() || st.Mode&0o004 == 0 || st.Size == 0 || st.Size > secretMaxFile:
						continue
					}
					files++
					out = scanSecretFile(out, p, &st, buf, skip)
				}
				if files > secretMaxFiles {
					f.Close()
					return out, files, nil
				}
				if err != nil || len(batch) == 0 {
					break
				}
			}
			f.Close()
			// Stay in the background: a short pause after each directory.
			time.Sleep(200 * time.Microsecond)
		}
	}
	return out, files, nil
}

func worldReadableFile(p string, st *syscall.Stat_t) bool {
	return syscall.Lstat(p, st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&0o004 != 0 && st.Size > 0 && st.Size <= secretMaxFile
}

func scanSecretFile(out []secretFile, p string, st *syscall.Stat_t, buf []byte, skip map[string]bool) []secretFile {
	if skip[p] {
		return out
	}
	uid, mode := st.Uid, st.Mode
	f, err := os.Open(p)
	if err != nil {
		return out
	}
	n, _ := io.ReadFull(bufio.NewReader(f), buf)
	f.Close()
	b := buf[:n]
	head := b
	if len(head) > 8192 {
		head = head[:8192]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return out // binary
	}
	if hits := findSecrets(filepath.Base(p), b); len(hits) > 0 {
		out = append(out, secretFile{path: p, uid: uid, mode: mode & 0o7777, hits: hits})
	}
	return out
}

type SecretState struct {
	Baselined bool            `json:"baselined"`
	Known     map[string]bool `json:"known"`
}

func secretStatePath(dir string) string { return filepath.Join(dir, "secrets.json") }

func (a *Agent) secretRoots() []string {
	if len(a.cfg.SecretRoots) > 0 {
		return a.cfg.SecretRoots
	}
	return secretRootsDefault
}

// diffSecrets reports findings not reported before. Findings that are gone
// are forgotten, so a secret that comes back is reported again.
func (a *Agent) diffSecrets(ss *SecretState, found []secretFile) {
	now := map[string]bool{}
	for _, f := range found {
		for _, h := range f.hits {
			k := f.path + "|" + h.Kind + "|" + h.FP
			now[k] = true
			if ss.Known[k] {
				continue
			}
			d := map[string]any{"path": f.path, "kind": h.Kind, "line": h.Line, "fingerprint": h.FP, "uid": f.uid,
				"mode": fmt.Sprintf("%04o", f.mode)}
			if !ss.Baselined {
				d["baseline"] = true
			}
			a.emit(proto.NewEvent("secret.exposed", d))
		}
	}
	ss.Known = now
	ss.Baselined = true
}

func (a *Agent) runSecrets(ctx context.Context) {
	ss := &SecretState{Known: map[string]bool{}}
	if raw, err := os.ReadFile(secretStatePath(a.cfg.StateDir)); err == nil {
		json.Unmarshal(raw, ss)
	}
	if ss.Known == nil {
		ss.Known = map[string]bool{}
	}
	t := time.NewTimer(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// Canaries look like secrets on purpose.
		skip := map[string]bool{}
		a.mu.Lock()
		for _, c := range a.state.Canaries {
			skip[c.Path] = true
		}
		a.mu.Unlock()
		_, all := suidRoots()
		roots := a.secretRoots()
		for _, r := range roots {
			delete(all, r)
		}
		start := time.Now()
		found, files, err := walkSecrets(ctx, roots, all, skip)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "secrets", "error": err.Error()}))
		} else {
			a.diffSecrets(ss, found)
			if raw, err := json.Marshal(ss); err == nil {
				writeFileAtomic(secretStatePath(a.cfg.StateDir), raw, 0o600)
			}
			a.emit(proto.NewEvent("secrets.scan", map[string]any{"files": files, "findings": len(ss.Known), "seconds": int(time.Since(start).Seconds())}))
		}
		t.Reset(secretEvery)
	}
}

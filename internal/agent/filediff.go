package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Contents of watched configuration files: the agent keeps the last seen
// copy of small text files (sudoers, sshd, cron, systemd units, PAM, shell
// init, passwd) in its state directory, so a change can be reported with
// the lines that changed instead of only a new hash. Password hashes
// (shadow, gshadow) and SSH keys are never copied, and lines that look like
// secrets are replaced before they leave the host.

const (
	contentMaxFile  = 64 << 10
	contentMaxTotal = 8 << 20
	diffMaxBytes    = 8 << 10
	diffContext     = 2
)

func contentDir(stateDir string) string { return filepath.Join(stateDir, "content") }

func contentPath(stateDir, path string) string {
	h := sha256.Sum256([]byte(path))
	return filepath.Join(contentDir(stateDir), hex.EncodeToString(h[:16]))
}

// diffable decides which watched files get their content kept.
func diffable(path string, st FileState) bool {
	base := filepath.Base(path)
	switch {
	case st.Hash == "" || st.Size > contentMaxFile || os.FileMode(st.Mode)&os.ModeSymlink != 0:
		return false
	case strings.Contains(base, "shadow") || strings.HasPrefix(base, "authorized_keys"):
		return false
	case strings.HasPrefix(path, "/etc/ssh/") && !strings.HasPrefix(base, "sshd_config"):
		return false // host keys
	}
	return true
}

func readText(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > contentMaxFile || bytes.IndexByte(b, 0) >= 0 {
		return nil, false
	}
	return b, true
}

// fileDiff adds the changed lines to a file event. old and cur are the
// known content; ok tells whether the old content was known.
func fileDiff(d map[string]any, path string, old []byte, oldKnown bool, cur []byte) {
	if !oldKnown {
		d["diff_note"] = "previous content unknown"
		return
	}
	text, truncated := unifiedDiff(filepath.Base(path), splitLines(old), splitLines(cur))
	if text == "" {
		return
	}
	d["diff"] = text
	if truncated {
		d["diff_truncated"] = true
	}
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	s := strings.TrimSuffix(string(b), "\n")
	return strings.Split(s, "\n")
}

// secretAssign catches settings whose value is a secret by its name
// (DB_PASSWORD=..., api_key: ...); secretWord the bare form "password x".
var (
	secretAssign = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|private[_-]?key|credentials?)[A-Za-z0-9_.-]*)(\s*[:=]\s*)("?)([^\s"]{3,})`)
	secretWord   = regexp.MustCompile(`(?i)\b(pass(?:word|wd|phrase)?|secret|token)(\s+)("?)([^\s"]{3,})`)
)

// redactLine replaces anything that looks like a secret.
func redactLine(name, line string) string {
	if hits := findSecrets(name, []byte(line)); len(hits) > 0 {
		return "[" + hits[0].Kind + " removed, " + hits[0].FP + "]"
	}
	line = secretAssign.ReplaceAllStringFunc(line, func(m string) string {
		sm := secretAssign.FindStringSubmatch(m)
		if n := strings.ToUpper(sm[1]); n == "NOPASSWD" || n == "PASSWD" {
			return m // sudo tags
		}
		return sm[1] + sm[2] + sm[3] + "[removed]"
	})
	return secretWord.ReplaceAllString(line, "${1}${2}${3}[removed]")
}

type diffOp struct {
	kind byte // ' ', '-', '+'
	line string
	no   int // line number in the new file (old file for '-')
}

// diffOps returns the edit script from a to b: common prefix and suffix are
// cut first, the rest is compared line by line when small enough and
// replaced as a whole otherwise.
func diffOps(a, b []string) []diffOp {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	var ops []diffOp
	for i := 0; i < pre; i++ {
		ops = append(ops, diffOp{' ', a[i], i + 1})
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]
	if len(ma)*len(mb) <= 250000 {
		n, m := len(ma), len(mb)
		lcs := make([]int32, (n+1)*(m+1))
		at := func(i, j int) int32 { return lcs[i*(m+1)+j] }
		for i := n - 1; i >= 0; i-- {
			for j := m - 1; j >= 0; j-- {
				if ma[i] == mb[j] {
					lcs[i*(m+1)+j] = at(i+1, j+1) + 1
				} else if at(i+1, j) >= at(i, j+1) {
					lcs[i*(m+1)+j] = at(i+1, j)
				} else {
					lcs[i*(m+1)+j] = at(i, j+1)
				}
			}
		}
		i, j := 0, 0
		for i < n || j < m {
			switch {
			case i < n && j < m && ma[i] == mb[j]:
				ops = append(ops, diffOp{' ', mb[j], pre + j + 1})
				i++
				j++
			case i < n && (j == m || at(i+1, j) >= at(i, j+1)):
				ops = append(ops, diffOp{'-', ma[i], pre + i + 1})
				i++
			default:
				ops = append(ops, diffOp{'+', mb[j], pre + j + 1})
				j++
			}
		}
	} else {
		for i, l := range ma {
			ops = append(ops, diffOp{'-', l, pre + i + 1})
		}
		for j, l := range mb {
			ops = append(ops, diffOp{'+', l, pre + j + 1})
		}
	}
	for k := 0; k < suf; k++ {
		ops = append(ops, diffOp{' ', b[len(b)-suf+k], len(b) - suf + k + 1})
	}
	return ops
}

// unifiedDiff renders the changes with two lines of context, secrets
// replaced, at most diffMaxBytes long.
func unifiedDiff(name string, a, b []string) (string, bool) {
	ops := diffOps(a, b)
	show := make([]bool, len(ops))
	changed := false
	for i, op := range ops {
		if op.kind == ' ' {
			continue
		}
		changed = true
		for k := i - diffContext; k <= i+diffContext; k++ {
			if k >= 0 && k < len(ops) {
				show[k] = true
			}
		}
	}
	if !changed {
		return "", false
	}
	var out strings.Builder
	gap := true
	for i, op := range ops {
		if !show[i] {
			gap = true
			continue
		}
		if gap {
			out.WriteString("@@ line " + strconv.Itoa(op.no) + "\n")
			gap = false
		}
		line := string(op.kind) + redactLine(name, op.line) + "\n"
		if out.Len()+len(line) > diffMaxBytes {
			return out.String(), true
		}
		out.WriteString(line)
	}
	return out.String(), false
}

// contentStore keeps the last content of diffable files.
type contentStore struct {
	dir   string
	total int64
}

func (a *Agent) contents() *contentStore {
	if a.content == nil {
		dir := contentDir(a.cfg.StateDir)
		os.MkdirAll(dir, 0o700)
		cs := &contentStore{dir: a.cfg.StateDir}
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if fi, err := e.Info(); err == nil {
					cs.total += fi.Size()
				}
			}
		}
		a.content = cs
	}
	return a.content
}

func (cs *contentStore) get(path string) ([]byte, bool) {
	b, err := os.ReadFile(contentPath(cs.dir, path))
	return b, err == nil
}

func (cs *contentStore) put(path string, b []byte) {
	p := contentPath(cs.dir, path)
	var old int64
	if fi, err := os.Stat(p); err == nil {
		old = fi.Size()
	}
	if cs.total-old+int64(len(b)) > contentMaxTotal {
		return
	}
	if writeFileAtomic(p, b, 0o600) == nil {
		cs.total += int64(len(b)) - old
	}
}

func (cs *contentStore) drop(path string) {
	p := contentPath(cs.dir, path)
	if fi, err := os.Stat(p); err == nil {
		if os.Remove(p) == nil {
			cs.total -= fi.Size()
		}
	}
}

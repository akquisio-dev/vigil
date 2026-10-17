package agent

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// DefaultWatch covers the places attackers use to persist or escalate.
var DefaultWatch = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
	"/etc/sudoers", "/etc/sudoers.d/*",
	"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*",
	"/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2",
	"/home/*/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys2",
	"/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
	"/etc/cron.weekly/*", "/etc/cron.monthly/*", "/var/spool/cron/crontabs/*",
	"/etc/systemd/system/*", "/etc/systemd/system/*/*",
	"/etc/ld.so.preload", "/etc/pam.d/*",
	"/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/root/.bashrc", "/root/.profile",
	"/etc/rc.local", "/etc/hosts",
}

// category maps a path to what it means for an attacker. The server turns
// categories into rules and ATT&CK techniques.
func category(path string) string {
	base := filepath.Base(path)
	switch {
	case strings.HasPrefix(base, "authorized_keys"):
		return "ssh_keys"
	case path == "/etc/passwd" || path == "/etc/shadow" || path == "/etc/group" || path == "/etc/gshadow":
		return "accounts"
	case strings.HasPrefix(path, "/etc/sudoers"):
		return "sudo"
	case strings.HasPrefix(path, "/etc/ssh/"):
		return "sshd"
	case strings.Contains(path, "cron"):
		return "cron"
	case strings.HasPrefix(path, "/etc/systemd/"):
		return "systemd"
	case path == "/etc/ld.so.preload":
		return "preload"
	case strings.HasPrefix(path, "/etc/pam.d/"):
		return "pam"
	case strings.Contains(path, "profile") || strings.Contains(path, "bashrc") || path == "/etc/rc.local":
		return "shell_init"
	}
	return "other"
}

const maxHashBytes = 16 << 20

// statFile hashes regular files and records symlinks by their target, which
// is how systemd *.wants entries show up.
func statFile(path string) (FileState, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return FileState{}, false
	}
	st := FileState{Size: fi.Size(), Mode: uint32(fi.Mode())}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.UID = sys.Uid
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		target, _ := os.Readlink(path)
		h := sha256.Sum256([]byte("link:" + target))
		st.Hash = hex.EncodeToString(h[:])
	case fi.Mode().IsRegular():
		f, err := os.Open(path)
		if err != nil {
			return FileState{}, false
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, io.LimitReader(f, maxHashBytes)); err != nil {
			return FileState{}, false
		}
		st.Hash = hex.EncodeToString(h.Sum(nil))
	default:
		return FileState{}, false
	}
	return st, true
}

func expand(globs []string) []string {
	seen := map[string]bool{}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			fi, err := os.Lstat(m)
			if err != nil || fi.IsDir() {
				continue
			}
			seen[m] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// scanFiles compares the watch list with the last known state. On the very
// first run it only records a baseline.
func (a *Agent) scanFiles() {
	globs := a.watchGlobs()

	first := !a.state.Initialized
	current := map[string]FileState{}
	for _, p := range expand(globs) {
		if st, ok := statFile(p); ok {
			current[p] = st
		}
	}

	cs := a.contents()
	if !first {
		for p, st := range current {
			old, known := a.state.Files[p]
			switch {
			case !known:
				d := fileData(p, st, FileState{})
				if diffable(p, st) {
					if cur, ok := readText(p); ok {
						fileDiff(d, p, nil, true, cur)
						cs.put(p, cur)
					}
				}
				a.emit(proto.NewEvent("file.added", d))
			case old.Hash != st.Hash || old.Mode != st.Mode || old.UID != st.UID:
				d := fileData(p, st, old)
				if old.Hash != st.Hash && diffable(p, st) {
					if cur, ok := readText(p); ok {
						prev, had := cs.get(p)
						fileDiff(d, p, prev, had, cur)
						cs.put(p, cur)
					}
				}
				a.emit(proto.NewEvent("file.changed", d))
			}
		}
		for p, old := range a.state.Files {
			if _, ok := current[p]; !ok {
				d := fileData(p, FileState{}, old)
				if prev, had := cs.get(p); had {
					fileDiff(d, p, prev, true, nil)
					cs.drop(p)
				}
				a.emit(proto.NewEvent("file.removed", d))
			}
		}
	}
	// The first scan, and the first after an upgrade, keeps a copy of every
	// diffable file, so the next change can be shown.
	if !a.contentSeeded {
		for p, st := range current {
			if !diffable(p, st) {
				continue
			}
			if _, had := cs.get(p); !had {
				if cur, ok := readText(p); ok {
					cs.put(p, cur)
				}
			}
		}
		a.contentSeeded = true
	}
	a.state.Files = current

	a.scanKeys(current, first)
	a.scanUsers(first)
}

func fileData(path string, now, old FileState) map[string]any {
	d := map[string]any{"path": path, "category": category(path)}
	if now.Hash != "" {
		d["hash"] = now.Hash
		d["size"] = now.Size
		d["mode"] = os.FileMode(now.Mode).String()
		d["uid"] = now.UID
	}
	if old.Hash != "" {
		d["old_hash"] = old.Hash
		if old.Mode != now.Mode && now.Hash != "" {
			d["old_mode"] = os.FileMode(old.Mode).String()
		}
		if old.UID != now.UID && now.Hash != "" {
			d["old_uid"] = old.UID
		}
	}
	return d
}

// AuthKey is one line of an authorized_keys file.
type AuthKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
	Options     string `json:"options,omitempty"`
}

var keyTypes = []string{"ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-", "sk-ssh-ed25519", "sk-ecdsa-sha2-"}

func isKeyType(s string) bool {
	for _, t := range keyTypes {
		if s == t || (strings.HasSuffix(t, "-") && strings.HasPrefix(s, t)) || strings.HasPrefix(s, t+"@") {
			return true
		}
	}
	return false
}

// splitKeyLine tokenizes on spaces while keeping quoted option values whole.
func splitKeyLine(line string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !quoted:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func ParseAuthorizedKeys(data []byte) []AuthKey {
	var keys []AuthKey
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := splitKeyLine(line)
		for i := 0; i+1 < len(f); i++ {
			if !isKeyType(f[i]) {
				continue
			}
			blob, err := base64.StdEncoding.DecodeString(f[i+1])
			if err != nil {
				break
			}
			sum := sha256.Sum256(blob)
			k := AuthKey{
				Type:        f[i],
				Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
				Comment:     strings.Join(f[i+2:], " "),
			}
			if i > 0 {
				k.Options = strings.Join(f[:i], " ")
			}
			keys = append(keys, k)
			break
		}
	}
	return keys
}

func (a *Agent) scanKeys(files map[string]FileState, first bool) {
	current := map[string][]AuthKey{}
	for p := range files {
		if category(p) != "ssh_keys" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		current[p] = ParseAuthorizedKeys(data)
	}
	if !first {
		for p, keys := range current {
			old := fpSet(a.state.Keys[p])
			for _, k := range keys {
				if !old[k.Fingerprint] {
					a.emit(proto.NewEvent("ssh.key_added", keyData(p, k)))
				}
			}
		}
		for p, keys := range a.state.Keys {
			now := fpSet(current[p])
			for _, k := range keys {
				if !now[k.Fingerprint] {
					a.emit(proto.NewEvent("ssh.key_removed", keyData(p, k)))
				}
			}
		}
	}
	a.state.Keys = current

	a.mu.Lock()
	a.keyNames = map[string]keyRef{}
	for p, keys := range current {
		for _, k := range keys {
			a.keyNames[k.Fingerprint] = keyRef{File: p, Comment: k.Comment}
		}
	}
	a.mu.Unlock()
}

// keyRef tells a login event which authorized_keys entry was used.
type keyRef struct {
	File    string
	Comment string
}

func fpSet(keys []AuthKey) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k.Fingerprint] = true
	}
	return m
}

func keyData(path string, k AuthKey) map[string]any {
	d := map[string]any{"file": path, "fingerprint": k.Fingerprint, "key_type": k.Type, "comment": k.Comment}
	if k.Options != "" {
		d["options"] = k.Options
	}
	return d
}

func (a *Agent) scanUsers(first bool) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	current := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		current[f[0]] = uid
	}
	if !first {
		for name, uid := range current {
			old, known := a.state.Users[name]
			if !known {
				a.emit(proto.NewEvent("user.added", map[string]any{"user": name, "uid": uid}))
			} else if old != uid {
				a.emit(proto.NewEvent("user.uid_changed", map[string]any{"user": name, "uid": uid, "old_uid": old}))
			}
		}
		for name, uid := range a.state.Users {
			if _, ok := current[name]; !ok {
				a.emit(proto.NewEvent("user.removed", map[string]any{"user": name, "uid": uid}))
			}
		}
	}
	a.state.Users = current
}

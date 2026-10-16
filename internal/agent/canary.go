package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

type CanaryState struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	Path    string    `json:"path"`
	Hash    string    `json:"hash,omitempty"`
	Ino     uint64    `json:"ino,omitempty"`
	Size    int64     `json:"size,omitempty"`
	MtimeNs int64     `json:"mtime_ns,omitempty"`
	Created time.Time `json:"created"`
	Status  string    `json:"status"` // active | tampered | error
	Error   string    `json:"error,omitempty"`
}

const maxCanaryBytes = 64 << 10

// Names that would turn a "canary" into persistence or a login path.
var deniedNames = []string{
	"authorized_keys", "authorized_keys2", "rc", "environment", "known_hosts",
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
	".zshrc", ".zprofile", ".zshenv", ".pam_environment", ".forward", ".netrc",
	"crontab", "ld.so.preload", "sudoers",
}

var deniedDirs = []string{"cron.d", "cron.hourly", "cron.daily", "systemd", "sudoers.d", "profile.d", "init.d", "pam.d", "rc.d", "bin", "sbin", "lib", "lib64"}

var deniedSuffixes = []string{".service", ".timer", ".socket", ".path", ".so", ".sh", ".py", ".pl", ".rb", ".php"}

func (a *Agent) validateCanaryPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return errors.New("path must be absolute and clean")
	}
	inside := false
	for _, r := range a.cfg.CanaryRoots {
		if strings.HasPrefix(p, r+"/") {
			inside = true
			break
		}
	}
	if !inside {
		return errors.New("path is outside canary_roots of this agent")
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) > 12 {
		return errors.New("path is too deep")
	}
	base := strings.ToLower(parts[len(parts)-1])
	if slices.Contains(deniedNames, base) || strings.HasPrefix(base, "authorized_keys") {
		return fmt.Errorf("file name %q is not allowed for canaries", base)
	}
	for _, s := range deniedSuffixes {
		if strings.HasSuffix(base, s) {
			return fmt.Errorf("file suffix %q is not allowed for canaries", s)
		}
	}
	for _, d := range parts[:len(parts)-1] {
		if slices.Contains(deniedDirs, strings.ToLower(d)) {
			return fmt.Errorf("directory %q is not allowed for canaries", d)
		}
	}
	return nil
}

// openParent walks to the parent directory with openat and O_NOFOLLOW, so a
// symlink anywhere on the way makes the operation fail instead of
// redirecting it.
func openParent(p string, create bool) (int, string, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for _, comp := range strings.Split(strings.TrimPrefix(filepath.Dir(p), "/"), "/") {
		if comp == "" {
			continue
		}
		const flags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		nfd, err := syscall.Openat(fd, comp, flags, 0)
		if err == syscall.ENOENT && create {
			if err = syscall.Mkdirat(fd, comp, 0o700); err == nil {
				nfd, err = syscall.Openat(fd, comp, flags, 0)
			}
		}
		syscall.Close(fd)
		if err != nil {
			return -1, "", fmt.Errorf("%s: %w", comp, err)
		}
		fd = nfd
	}
	return fd, filepath.Base(p), nil
}

func (a *Agent) placeCanary(c proto.Canary) (*CanaryState, error) {
	if !slices.Contains(proto.CanaryTypes, c.Type) {
		return nil, fmt.Errorf("unknown canary type %q", c.Type)
	}
	if err := a.validateCanaryPath(c.Path); err != nil {
		return nil, err
	}
	content, err := GenerateCanary(c.Type, c.Params)
	if err != nil {
		return nil, err
	}
	if len(content) > maxCanaryBytes {
		return nil, errors.New("generated content too large")
	}
	dfd, base, err := openParent(c.Path, true)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dfd)
	fd, err := syscall.Openat(dfd, base, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if err == syscall.EEXIST {
			return nil, errors.New("a file already exists at this path, canaries never overwrite")
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), c.Path)
	defer f.Close()
	if _, err := f.Write(content); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	return &CanaryState{
		ID: c.ID, Type: c.Type, Path: c.Path, Hash: hex.EncodeToString(sum[:]),
		Ino: st.Ino, Size: st.Size, MtimeNs: st.Mtim.Nano(), Created: time.Now().UTC(), Status: "active",
	}, nil
}

// removeCanary deletes only the exact file the agent created.
func removeCanary(cs *CanaryState) error {
	if cs.Status == "error" {
		return nil
	}
	dfd, base, err := openParent(cs.Path, false)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return err
	}
	defer syscall.Close(dfd)
	// Inode numbers get reused right away, so identity is inode plus
	// content. O_NOFOLLOW refuses a symlink planted in its place.
	fd, err := syscall.Openat(dfd, base, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return nil
		}
		return err
	}
	f := os.NewFile(uintptr(fd), cs.Path)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Ino != cs.Ino || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Size > maxCanaryBytes {
		return errors.New("file was replaced, not deleting it")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCanaryBytes+1))
	if err != nil {
		return err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != cs.Hash {
		return errors.New("file content changed, not deleting it")
	}
	return syscall.Unlinkat(dfd, base)
}

// applyConfig reconciles the canaries on disk with the signed config.
func (a *Agent) applyConfig(cfg proto.AgentConfig) {
	want := map[string]proto.Canary{}
	for _, c := range cfg.Canaries {
		want[c.ID] = c
	}
	for id, cs := range a.state.Canaries {
		c, keep := want[id]
		if keep && c.Path == cs.Path && cs.Status != "error" {
			continue
		}
		if err := removeCanary(cs); err != nil {
			a.emit(proto.NewEvent("canary.remove_failed", map[string]any{"canary_id": id, "path": cs.Path, "error": err.Error()}))
			if !keep {
				delete(a.state.Canaries, id)
			}
			continue
		}
		if cs.Status != "error" {
			a.emit(proto.NewEvent("canary.removed", map[string]any{"canary_id": id, "path": cs.Path}))
		}
		delete(a.state.Canaries, id)
	}
	for id, c := range want {
		if _, ok := a.state.Canaries[id]; ok {
			continue
		}
		cs, err := a.placeCanary(c)
		if err != nil {
			a.state.Canaries[id] = &CanaryState{ID: id, Type: c.Type, Path: c.Path, Created: time.Now().UTC(), Status: "error", Error: err.Error()}
			a.emit(proto.NewEvent("canary.error", map[string]any{"canary_id": id, "path": c.Path, "error": err.Error()}))
			continue
		}
		a.state.Canaries[id] = cs
		a.emit(proto.NewEvent("canary.placed", map[string]any{"canary_id": id, "path": c.Path, "type": c.Type, "hash": cs.Hash}))
	}
	a.state.ConfigVersion = cfg.Version
	a.remarkCanaries()
	a.runActions(cfg.Actions)
}

// checkCanaries notices canaries that were deleted, replaced or edited.
// It compares metadata first and only rereads content when that changed.
func (a *Agent) checkCanaries() {
	for id, cs := range a.state.Canaries {
		if cs.Status != "active" {
			continue
		}
		var st syscall.Stat_t
		problem := ""
		if err := syscall.Lstat(cs.Path, &st); err != nil {
			problem = "missing"
		} else if st.Ino != cs.Ino || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			problem = "replaced"
		} else if st.Size != cs.Size || st.Mtim.Nano() != cs.MtimeNs {
			data, err := os.ReadFile(cs.Path)
			sum := sha256.Sum256(data)
			if err != nil || hex.EncodeToString(sum[:]) != cs.Hash {
				problem = "modified"
			} else {
				cs.Size, cs.MtimeNs = st.Size, st.Mtim.Nano()
			}
		}
		if problem != "" {
			cs.Status = "tampered"
			a.emit(proto.NewEvent("canary.tampered", map[string]any{"canary_id": id, "path": cs.Path, "problem": problem}))
		}
	}
	a.remarkCanaries()
}

func (a *Agent) activeCanaryPaths() map[string]string {
	paths := map[string]string{}
	for id, cs := range a.state.Canaries {
		if cs.Status == "active" {
			paths[cs.Path] = id
		}
	}
	return paths
}

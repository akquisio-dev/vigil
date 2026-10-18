package server

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/backup"
)

// A backup is a gzipped tar: the data directory under data/, the config
// file and the files it points to under config/<absolute path>, and
// MANIFEST.json last, with a SHA-256 per file and the event chain head.
// Downloaded caches (block lists, geo and vulnerability data) are left out;
// the server fetches them again.

const backupFormat = 1

type BackupManifest struct {
	Format    int          `json:"format"`
	Version   string       `json:"version"`
	Created   time.Time    `json:"created"`
	Host      string       `json:"host"`
	DataDir   string       `json:"data_dir"`
	Recipient string       `json:"recipient,omitempty"` // key fingerprint
	Files     []BackupFile `json:"files"`
	Skipped   []string     `json:"skipped,omitempty"`
	ChainSeq  uint64       `json:"chain_seq"`
	ChainHead string       `json:"chain_head"`
}

type BackupFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// backupCache reports data dir entries that are downloads, not state.
func backupCache(rel string) bool {
	switch {
	case rel == "intel" || strings.HasPrefix(rel, "intel/"),
		rel == "geo" || strings.HasPrefix(rel, "geo/"):
		return true
	case strings.HasPrefix(rel, "vuln/"):
		return !strings.HasPrefix(path.Base(rel), "packages-")
	}
	return strings.HasPrefix(path.Base(rel), ".")
}

// chainCheck follows the event hash chain across files as they stream by.
type chainCheck struct {
	prev string
	seq  uint64
	err  error
	part []byte
	file string
	line int
}

func (c *chainCheck) Write(p []byte) (int, error) {
	c.part = append(c.part, p...)
	for {
		i := bytes.IndexByte(c.part, '\n')
		if i < 0 {
			return len(p), nil
		}
		c.lineDone(c.part[:i])
		c.part = c.part[i+1:]
	}
}

func (c *chainCheck) lineDone(b []byte) {
	c.line++
	if c.err != nil {
		return
	}
	var cl chainLine
	if err := json.Unmarshal(b, &cl); err != nil {
		c.err = fmt.Errorf("%s:%d: unreadable line", c.file, c.line)
		return
	}
	if cl.Prev != c.prev || chainHash(cl.Prev, cl.Rec) != cl.Hash {
		c.err = fmt.Errorf("%s:%d: hash chain broken", c.file, c.line)
		return
	}
	var r struct {
		Seq uint64 `json:"seq"`
	}
	if json.Unmarshal(cl.Rec, &r) == nil && r.Seq > c.seq {
		c.seq = r.Seq
	}
	c.prev = cl.Hash
}

func (c *chainCheck) next(file string) error {
	if len(c.part) > 0 && c.err == nil {
		c.err = fmt.Errorf("%s: last line incomplete", c.file)
	}
	c.part, c.file, c.line = nil, file, 0
	return c.err
}

// BackupOptions says where a backup goes.
type BackupOptions struct {
	ConfigPath string
	Recipient  *ecdh.PublicKey // nil writes a plain, unsealed backup
}

// WriteBackup writes one backup of cfg's server to w. It is safe while the
// server runs: state and account files are replaced by rename, so each copy
// is whole, and event logs are copied up to their last complete line after
// the files that refer to them.
func WriteBackup(cfg *Config, opt BackupOptions, w io.Writer) (*BackupManifest, error) {
	host, _ := os.Hostname()
	m := &BackupManifest{Format: backupFormat, Version: Version, Created: time.Now().UTC(), Host: host, DataDir: cfg.DataDir}
	out := w
	var sealer io.WriteCloser
	if opt.Recipient != nil {
		var err error
		if sealer, err = backup.Seal(w, opt.Recipient); err != nil {
			return nil, err
		}
		out = sealer
		m.Recipient = backup.Fingerprint(opt.Recipient)
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)

	add := func(name, src string, limit int64, tee io.Writer) error {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		size := st.Size()
		if limit >= 0 {
			size = limit
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: st.ModTime(), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		h := sha256.New()
		dst := io.MultiWriter(tw, h)
		if tee != nil {
			dst = io.MultiWriter(dst, tee)
		}
		if _, err := io.CopyN(dst, f, size); err != nil {
			return fmt.Errorf("%s: %w", src, err)
		}
		m.Files = append(m.Files, BackupFile{Path: name, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))})
		return nil
	}

	// State first, then the chain anchor, then the events: the events
	// copied last always cover everything the state refers to.
	var state, events []string
	err := filepath.WalkDir(cfg.DataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(cfg.DataDir, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if backupCache(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch {
		case rel == "events/ANCHOR":
		case strings.HasPrefix(rel, "events/") && strings.HasSuffix(rel, ".jsonl"):
			events = append(events, rel)
		default:
			state = append(state, rel)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(state)
	sort.Strings(events)
	for _, rel := range state {
		if err := add("data/"+rel, filepath.Join(cfg.DataDir, rel), -1, nil); err != nil {
			return nil, err
		}
	}
	cc := &chainCheck{}
	anchor := filepath.Join(cfg.DataDir, "events", "ANCHOR")
	if raw, err := os.ReadFile(anchor); err == nil {
		cc.prev = strings.TrimSpace(string(raw))
		if err := add("data/events/ANCHOR", anchor, -1, nil); err != nil {
			return nil, err
		}
	}
	for _, rel := range events {
		src := filepath.Join(cfg.DataDir, rel)
		n, err := completeLines(src)
		if err != nil {
			return nil, err
		}
		cc.next(path.Base(rel))
		if err := add("data/"+rel, src, n, cc); err != nil {
			return nil, err
		}
	}
	if err := cc.next(""); err != nil {
		return nil, fmt.Errorf("event chain in the copy: %w", err)
	}
	m.ChainSeq, m.ChainHead = cc.seq, cc.prev

	if opt.ConfigPath != "" {
		abs, _ := filepath.Abs(opt.ConfigPath)
		for _, p := range configFiles(cfg, abs) {
			if err := add("config"+filepath.ToSlash(p), p, -1, nil); err != nil {
				if errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) {
					m.Skipped = append(m.Skipped, p)
					continue
				}
				return nil, err
			}
		}
	}

	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := tw.WriteHeader(&tar.Header{Name: "MANIFEST.json", Mode: 0o600, Size: int64(len(raw)), ModTime: m.Created, Typeflag: tar.TypeReg}); err != nil {
		return nil, err
	}
	if _, err := tw.Write(raw); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if sealer != nil {
		if err := sealer.Close(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// completeLines is the size of the file up to its last newline, so a line
// the server is writing right now is left for the next backup.
func completeLines(p string) (int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	end := st.Size()
	buf := make([]byte, 64<<10)
	for end > 0 {
		n := int64(len(buf))
		if n > end {
			n = end
		}
		if _, err := f.ReadAt(buf[:n], end-n); err != nil {
			return 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			return end - n + int64(i) + 1, nil
		}
		end -= n
	}
	return 0, nil
}

// configFiles lists the config file and the files it names.
func configFiles(cfg *Config, cfgPath string) []string {
	out := []string{cfgPath}
	if b := cfg.Brand; b != nil {
		for _, p := range []string{b.Logo, b.Icon} {
			if p != "" {
				out = append(out, p)
			}
		}
	}
	for _, dir := range []string{cfg.YaraDir, cfg.SigmaDir, cfg.RulesDir} {
		if dir == "" {
			continue
		}
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				out = append(out, p)
			}
			return nil
		})
	}
	for i, p := range out {
		if abs, err := filepath.Abs(p); err == nil {
			out[i] = abs
		}
	}
	sort.Strings(out[1:])
	return out
}

// backupName is the file name for a backup made at t; the timestamp sorts.
func backupName(t time.Time) string {
	return "vigil-backup-" + t.UTC().Format("20060102T150405Z") + ".vbak"
}

func isBackupName(n string) bool {
	return strings.HasPrefix(n, "vigil-backup-") && strings.HasSuffix(n, ".vbak") && len(n) == len(backupName(time.Time{}))
}

// BackupToDir writes a sealed backup into dir, then keeps only the newest
// keep backups. A backup is renamed into place only once it is complete.
func BackupToDir(cfg *Config, opt BackupOptions, dir string, keep int) (string, *BackupManifest, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	var m *BackupManifest
	var final string
	// The daily prune can drop the oldest event file between reading the
	// anchor and the events; a second try sees the new anchor.
	for try := 0; ; try++ {
		tmp, err := os.CreateTemp(dir, ".vigil-backup-*")
		if err != nil {
			return "", nil, err
		}
		m, err = WriteBackup(cfg, opt, tmp)
		if err == nil {
			err = tmp.Sync()
		}
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(tmp.Name())
			if try == 0 && strings.Contains(err.Error(), "event chain") {
				continue
			}
			return "", nil, err
		}
		final = filepath.Join(dir, backupName(m.Created))
		if err := os.Rename(tmp.Name(), final); err != nil {
			os.Remove(tmp.Name())
			return "", nil, err
		}
		break
	}
	if keep > 0 {
		names, _ := listBackups(dir)
		for i := 0; i < len(names)-keep; i++ {
			os.Remove(filepath.Join(dir, names[i]))
		}
	}
	return final, m, nil
}

// listBackups returns the backup file names in dir, oldest first.
func listBackups(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() && isBackupName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// readBackup walks a backup, plain or sealed, and checks every file
// against the manifest and the event chain. Each data file is handed to
// fn (if set) while it is read; fn must consume r.
func readBackup(r io.Reader, key *ecdh.PrivateKey, fn func(name string, r io.Reader) error) (*BackupManifest, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(len("vigil-backup 1\n"))
	var in io.Reader = br
	if backup.IsSealed(head) {
		if key == nil {
			return nil, errors.New("the backup is sealed; give the secret key with -key")
		}
		var err error
		if in, err = backup.Open(br, key); err != nil {
			return nil, err
		}
	}
	gz, err := gzip.NewReader(in)
	if errors.Is(err, backup.ErrDamaged) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("not a vigil backup: %w", err)
	}
	tr := tar.NewReader(gz)
	seen := map[string]string{}
	var order []string
	var m *BackupManifest
	cc := &chainCheck{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, backupErr(err)
		}
		if m != nil {
			return nil, errors.New("entries after the manifest")
		}
		if h.Typeflag != tar.TypeReg || !validEntry(h.Name) {
			return nil, fmt.Errorf("unexpected entry %q", h.Name)
		}
		if h.Name == "MANIFEST.json" {
			raw, err := io.ReadAll(io.LimitReader(tr, 16<<20))
			if err != nil {
				return nil, backupErr(err)
			}
			m = &BackupManifest{}
			if err := json.Unmarshal(raw, m); err != nil {
				return nil, fmt.Errorf("manifest: %w", err)
			}
			continue
		}
		if _, dup := seen[h.Name]; dup {
			return nil, fmt.Errorf("%s appears twice", h.Name)
		}
		hs := sha256.New()
		var src io.Reader = io.TeeReader(tr, hs)
		isEvents := strings.HasPrefix(h.Name, "data/events/") && strings.HasSuffix(h.Name, ".jsonl")
		if h.Name == "data/events/ANCHOR" {
			raw, err := io.ReadAll(io.LimitReader(tr, 1024))
			if err != nil {
				return nil, backupErr(err)
			}
			hs.Write(raw)
			cc.prev = strings.TrimSpace(string(raw))
			src = bytes.NewReader(raw)
		} else if isEvents {
			if err := cc.next(path.Base(h.Name)); err != nil {
				return nil, fmt.Errorf("event chain: %w", err)
			}
			src = io.TeeReader(src, cc)
		}
		if fn != nil {
			err = fn(h.Name, src)
		} else {
			_, err = io.Copy(io.Discard, src)
		}
		if err != nil {
			return nil, backupErr(err)
		}
		seen[h.Name] = hex.EncodeToString(hs.Sum(nil))
		order = append(order, h.Name)
	}
	// The gzip trailer and, for sealed backups, the last chunk are only
	// checked once the reader reaches the end.
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return nil, backupErr(err)
	}
	if m == nil {
		return nil, errors.New("backup has no manifest (cut off?)")
	}
	if m.Format != backupFormat {
		return nil, fmt.Errorf("backup format %d is not supported", m.Format)
	}
	if err := cc.next(""); err != nil {
		return nil, fmt.Errorf("event chain: %w", err)
	}
	if len(m.Files) != len(order) {
		return nil, fmt.Errorf("manifest lists %d files, backup holds %d", len(m.Files), len(order))
	}
	for i, f := range m.Files {
		if f.Path != order[i] || seen[f.Path] != f.SHA256 {
			return nil, fmt.Errorf("%s does not match the manifest", f.Path)
		}
	}
	if cc.prev != m.ChainHead || cc.seq != m.ChainSeq {
		return nil, errors.New("event chain head does not match the manifest")
	}
	return m, nil
}

func backupErr(err error) error {
	if errors.Is(err, backup.ErrDamaged) {
		return err
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, gzip.ErrChecksum) || errors.Is(err, gzip.ErrHeader) {
		return fmt.Errorf("backup is cut off or damaged: %w", err)
	}
	return err
}

func validEntry(name string) bool {
	if name == "MANIFEST.json" {
		return true
	}
	clean := path.Clean(name)
	if clean != name || strings.Contains(name, "\\") {
		return false
	}
	if rest, ok := strings.CutPrefix(name, "data/"); ok {
		return rest != "" && !strings.HasPrefix(rest, "../") && rest != ".."
	}
	if rest, ok := strings.CutPrefix(name, "config/"); ok {
		return rest != "" && !strings.Contains("/"+rest+"/", "/../")
	}
	return false
}

// CheckBackup reads a whole backup and checks it without writing anything.
func CheckBackup(r io.Reader, key *ecdh.PrivateKey) (*BackupManifest, error) {
	return readBackup(r, key, nil)
}

// RestoreOptions says where a backup is restored to.
type RestoreOptions struct {
	DataDir   string
	ConfigOut string // where the config files go; empty leaves them out
	Force     bool   // allow a backup made by a newer vigil
}

// RestoreResult tells the operator what changed on disk.
type RestoreResult struct {
	Manifest *BackupManifest
	OldData  string   // where the previous data directory was moved
	Config   []string // config files written
}

// RestoreBackup unpacks a backup into a new directory next to the data
// directory, checks it completely, and only then swaps it in. The previous
// data directory is moved aside, never deleted. It refuses to run while a
// server holds the data directory.
func RestoreBackup(r io.Reader, key *ecdh.PrivateKey, opt RestoreOptions) (*RestoreResult, error) {
	dataDir := filepath.Clean(opt.DataDir)
	if _, err := os.Stat(dataDir); err == nil {
		unlock, err := lockDataDir(dataDir)
		if err != nil {
			return nil, err
		}
		defer unlock()
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	tmp := dataDir + ".restore-" + stamp
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	var cfgFiles [][2]string // name in backup, staged copy
	stageCfg := tmp + ".config"
	defer os.RemoveAll(stageCfg)
	m, err := readBackup(r, key, func(name string, src io.Reader) error {
		var dst string
		if rest, ok := strings.CutPrefix(name, "data/"); ok {
			dst = filepath.Join(tmp, filepath.FromSlash(rest))
		} else {
			if opt.ConfigOut == "" {
				_, err := io.Copy(io.Discard, src)
				return err
			}
			dst = filepath.Join(stageCfg, strconv.Itoa(len(cfgFiles)))
			cfgFiles = append(cfgFiles, [2]string{strings.TrimPrefix(name, "config"), dst})
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, src); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	})
	if err != nil {
		return nil, err
	}
	if newerVersion(m.Version, Version) && !opt.Force {
		return nil, fmt.Errorf("the backup was made by vigil %s, this is %s; update first or pass -force", m.Version, Version)
	}
	// The restored log must open as the server will open it.
	st, err := OpenStore(filepath.Join(tmp, "events"), 1)
	if err != nil {
		return nil, err
	}
	if !st.ChainOK {
		return nil, fmt.Errorf("restored event chain: %s", st.ChainError)
	}
	if _, err := LoadState(tmp); err != nil {
		return nil, fmt.Errorf("restored state: %w", err)
	}

	res := &RestoreResult{Manifest: m}
	uid, gid, own := dataOwner(dataDir)
	if own {
		filepath.WalkDir(tmp, func(p string, d fs.DirEntry, err error) error {
			if err == nil {
				os.Lchown(p, uid, gid)
			}
			return nil
		})
	}
	if _, err := os.Stat(dataDir); err == nil {
		res.OldData = dataDir + ".before-restore-" + stamp
		if err := os.Rename(dataDir, res.OldData); err != nil {
			return nil, err
		}
	}
	if err := os.Rename(tmp, dataDir); err != nil {
		if res.OldData != "" {
			os.Rename(res.OldData, dataDir)
		}
		return nil, err
	}
	ok = true

	for _, c := range cfgFiles {
		dst := filepath.Join(opt.ConfigOut, filepath.FromSlash(c[0]))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return res, err
		}
		if err := os.Rename(c[1], dst); err != nil {
			return res, err
		}
		res.Config = append(res.Config, dst)
	}
	return res, nil
}

// dataOwner is who must own a restored data directory: the owner of the
// one it replaces, else the vigil user. Only root can hand files over.
func dataOwner(dataDir string) (int, int, bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	if fi, err := os.Stat(dataDir); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return int(st.Uid), int(st.Gid), true
		}
	}
	if u, err := user.Lookup("vigil"); err == nil {
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		return uid, gid, true
	}
	log.Printf("restore: no vigil user; the data directory stays owned by root")
	return 0, 0, false
}

// lockDataDir takes the lock a running server holds on its data directory.
func lockDataDir(dir string) (func(), error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s is in use by a running vigil-server; stop it first", dir)
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}

// newerVersion reports whether a is a later release than b. Builds that
// are not releases ("dev", commit ids) never count as newer.
func newerVersion(a, b string) bool {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return false
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v, _, _ = strings.Cut(strings.TrimPrefix(v, "v"), "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// checkBackupAge raises server.backup_stale when the newest backup is too old and
// resolves it when a fresh one appears. Caller holds s.mu.
func (s *Server) checkBackupAge(now time.Time) []*Alert {
	b := s.cfg.Backup
	if b == nil {
		return nil
	}
	newest := time.Time{}
	names, err := listBackups(b.Dir)
	if len(names) > 0 {
		if fi, err := os.Stat(filepath.Join(b.Dir, names[len(names)-1])); err == nil {
			newest = fi.ModTime()
		}
	}
	limit := time.Duration(b.MaxAgeHours) * time.Hour
	// Give a new installation one period before the first complaint.
	if newest.IsZero() && now.Sub(s.started) < limit {
		return nil
	}
	if !newest.IsZero() && now.Sub(newest) <= limit {
		s.resolveKey("server.backup_stale", "system")
		return nil
	}
	age := "never"
	if !newest.IsZero() {
		age = fmtDuration(now.Sub(newest))
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		age = clip(err.Error(), 120)
	}
	return s.raise([]finding{{Rule: "server.backup_stale", Key: "server.backup_stale", Params: map[string]string{"dir": b.Dir, "age": age}}}, "", 0)
}

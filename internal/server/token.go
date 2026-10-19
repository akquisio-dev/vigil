package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// newEnrollTokenLocked adds a one-time enrollment token, valid for an hour, and
// records who made it. Caller holds s.mu.
func (s *Server) newEnrollTokenLocked(by string) (string, *EnrollToken) {
	tok := "vgl_" + newID(24)
	t := &EnrollToken{Hash: sha(tok), Created: time.Now().UTC(), Expires: time.Now().UTC().Add(time.Hour), By: by}
	s.state.Tokens[t.Hash] = t
	s.saveLocked()
	return tok, t
}

// CreateEnrollToken makes an enrollment token without the dashboard, for
// setting up a server from a script. It takes the data directory lock, so
// it refuses while the server runs: the server would not see the token and
// overwrite it with its own state on the next save.
func CreateEnrollToken(cfg *Config, by string) (string, time.Time, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return "", time.Time{}, err
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return "", time.Time{}, err
	}
	defer unlock()
	s, err := New(cfg)
	if err != nil {
		return "", time.Time{}, err
	}
	s.mu.Lock()
	tok, t := s.newEnrollTokenLocked(by)
	s.mu.Unlock()
	s.audit(by, "enroll.token_created", map[string]any{"expires": t.Expires, "via": "cli"})
	// Run as root on a data directory the server user owns: hand the
	// files written here over, or the server cannot replace them.
	if uid, gid, ok := dataOwner(cfg.DataDir); ok {
		filepath.WalkDir(cfg.DataDir, func(p string, d fs.DirEntry, err error) error {
			if err == nil {
				os.Lchown(p, uid, gid)
			}
			return nil
		})
	}
	return tok, t.Expires, nil
}

package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Users live in their own file so `vigil-server user add` works while the
// server is running: the server rereads the file on every login.
var usersMu sync.Mutex

func usersFile(dir string) string { return filepath.Join(dir, "users.json") }

func LoadUsers(dir string) (map[string]*User, error) {
	users := map[string]*User{}
	raw, err := os.ReadFile(usersFile(dir))
	if errors.Is(err, os.ErrNotExist) {
		return users, nil
	}
	if err != nil {
		return nil, err
	}
	return users, json.Unmarshal(raw, &users)
}

func SaveUsers(dir string, users map[string]*User) error {
	raw, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".users-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	// `vigil-server user add` run as root must not leave a root-owned file
	// that the service user cannot read.
	if fi, err := os.Stat(dir); err == nil && os.Geteuid() == 0 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			if err := tmp.Chown(int(st.Uid), int(st.Gid)); err != nil {
				tmp.Close()
				return err
			}
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), usersFile(dir))
}

// UpdateUsers applies fn to the user file under a process-wide lock.
func UpdateUsers(dir string, fn func(map[string]*User) error) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	users, err := LoadUsers(dir)
	if err != nil {
		return err
	}
	if err := fn(users); err != nil {
		return err
	}
	return SaveUsers(dir, users)
}

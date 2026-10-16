package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// State is what the agent remembers between runs. Comparing against it on
// start reveals changes that happened while the agent was not running.
type State struct {
	Files    map[string]FileState    `json:"files"`
	Keys     map[string][]AuthKey    `json:"keys"`  // authorized_keys path -> keys
	Users    map[string]int          `json:"users"` // name -> uid
	Ports    []Port                  `json:"ports"`
	Canaries map[string]*CanaryState `json:"canaries"`

	ConfigVersion int64 `json:"config_version"`
	Initialized   bool  `json:"initialized"`
	// JournalCursor lets the agent pick up SSH and sudo entries that were
	// written while it was not running.
	JournalCursor string `json:"journal_cursor,omitempty"`
	// Offsets of followed log files, so lines written while the agent was
	// down are read on start.
	Offsets map[string]LogOffset `json:"offsets,omitempty"`
	Updates UpdateState          `json:"updates"`
}

type LogOffset struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

type FileState struct {
	Hash string `json:"hash"`
	Size int64  `json:"size"`
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
}

func statePath(dir string) string { return filepath.Join(dir, "state.json") }

func LoadState(dir string) (*State, error) {
	s := &State{
		Files:    map[string]FileState{},
		Keys:     map[string][]AuthKey{},
		Users:    map[string]int{},
		Canaries: map[string]*CanaryState{},
		Offsets:  map[string]LogOffset{},
	}
	raw, err := os.ReadFile(statePath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, err
	}
	if s.Files == nil {
		s.Files = map[string]FileState{}
	}
	if s.Keys == nil {
		s.Keys = map[string][]AuthKey{}
	}
	if s.Users == nil {
		s.Users = map[string]int{}
	}
	if s.Canaries == nil {
		s.Canaries = map[string]*CanaryState{}
	}
	if s.Offsets == nil {
		s.Offsets = map[string]LogOffset{}
	}
	return s, nil
}

func (s *State) Save(dir string) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(dir), raw, 0o600)
}

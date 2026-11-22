package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	// CurrentVersion is the current on-disk schema version for state.json.
	CurrentVersion = 1

	stateFileMode fs.FileMode = 0o600
	stateDirMode  fs.FileMode = 0o750
)

// FileRecord tracks metadata and ownership for an installed quadlet or data file.
type FileRecord struct {
	SHA256    string      `json:"sha256"`
	Mode      fs.FileMode `json:"mode"`
	OwnerUID  int         `json:"owner_uid"`
	OwnerGID  int         `json:"owner_gid"`
	Component string      `json:"component"`
	Kind      string      `json:"kind"`
}

// ManagedNetworkRecord tracks a NetworkManager connection profile referenced or owned by quadmatic.
type ManagedNetworkRecord struct {
	ConnectionName string `json:"connection_name"`
	Kind           string `json:"kind"` // vlan|vrf|macvlan
	Owned          bool   `json:"owned"`
	Component      string `json:"component"`
	Scope          string `json:"scope"`
}

// State represents the persisted host convergence state stored in state.json.
type State struct {
	Version        int                    `json:"version"`
	AppliedSHA     string                 `json:"applied_sha"`
	AppliedAt      time.Time              `json:"applied_at"`
	ManagedUsers   []string               `json:"managed_users"`
	Files          map[string]FileRecord  `json:"files"`
	GeneratedUnits map[string]string      `json:"generated_units"`
	Secrets        map[string]string      `json:"secrets"`
	Networks       []ManagedNetworkRecord `json:"networks"`
	NFTablesHash   string                 `json:"nftables_hash"`
}

// NewEmpty returns a new empty State with initialized maps and slices at CurrentVersion.
func NewEmpty() *State {
	return &State{
		Version:        CurrentVersion,
		ManagedUsers:   []string{},
		Files:          make(map[string]FileRecord),
		GeneratedUnits: make(map[string]string),
		Secrets:        make(map[string]string),
		Networks:       []ManagedNetworkRecord{},
	}
}

func (s *State) initNilFields() {
	if s.ManagedUsers == nil {
		s.ManagedUsers = []string{}
	}
	if s.Files == nil {
		s.Files = make(map[string]FileRecord)
	}
	if s.GeneratedUnits == nil {
		s.GeneratedUnits = make(map[string]string)
	}
	if s.Secrets == nil {
		s.Secrets = make(map[string]string)
	}
	if s.Networks == nil {
		s.Networks = []ManagedNetworkRecord{}
	}
}

// Load reads and decodes the persisted State from path.
// When path does not exist, Load returns NewEmpty(), nil.
func Load(path string) (*State, error) {
	if path == "" {
		return nil, errors.New("state path must not be empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewEmpty(), nil
		}
		return nil, fmt.Errorf("read state %q: %w", path, err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("decode state %q: %w", path, err)
	}
	s.initNilFields()
	return &s, nil
}

// SaveAtomic writes s as indented JSON to path using a 0600 temporary file in the
// same directory, fsyncing it, and atomically renaming it into place.
func SaveAtomic(path string, s *State) error {
	if path == "" {
		return errors.New("state path must not be empty")
	}
	if s == nil {
		return errors.New("state must not be nil")
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, stateDirMode); err != nil {
		return fmt.Errorf("create state directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(stateFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp state file %q: %w", tmpName, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp state file %q: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp state file %q: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file %q: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp state file %q to %q: %w", tmpName, path, err)
	}
	cleanup = false

	// Best-effort directory fsync so the renamed entry is durable across crashes.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	return nil
}

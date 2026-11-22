package state

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadMissingFileReturnsInitializedEmptyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "state.json")

	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load missing file failed: %v", err)
	}
	if s == nil {
		t.Fatal("Load returned nil state")
	}
	if s.Version != CurrentVersion {
		t.Fatalf("expected Version %d, got %d", CurrentVersion, s.Version)
	}
	if s.AppliedSHA != "" {
		t.Fatalf("expected empty AppliedSHA, got %q", s.AppliedSHA)
	}
	if !s.AppliedAt.IsZero() {
		t.Fatalf("expected zero AppliedAt, got %v", s.AppliedAt)
	}
	if s.ManagedUsers == nil {
		t.Fatal("expected non-nil ManagedUsers slice")
	}
	if s.Files == nil {
		t.Fatal("expected non-nil Files map")
	}
	if s.GeneratedUnits == nil {
		t.Fatal("expected non-nil GeneratedUnits map")
	}
	if s.Secrets == nil {
		t.Fatal("expected non-nil Secrets map")
	}
	if s.SecretSourcePaths == nil {
		t.Fatal("expected non-nil SecretSourcePaths map")
	}
	if s.Networks == nil {
		t.Fatal("expected non-nil Networks slice")
	}

	// Ensure map writes do not panic.
	s.Files["/etc/containers/systemd/caddy.container"] = FileRecord{SHA256: "abc", Scope: "rootful"}
	s.GeneratedUnits["rootful/caddy.service"] = "def"
	s.Secrets["rootful/api_key"] = "ghi"
	s.SecretSourcePaths["rootful/api_key"] = "secrets/api_key.age"
}

func TestLoadPartialJSONInitializesNilMapsAndSlices(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantSHA string
	}{
		{
			name:    "empty object",
			content: "{}",
		},
		{
			name:    "explicit nulls and omitted keys",
			content: `{"applied_sha":"deadbeef","managed_users":null,"files":null,"generated_units":null,"secrets":null,"secret_source_paths":null,"networks":null}`,
			wantSHA: "deadbeef",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			s, err := Load(path)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			if s.AppliedSHA != tc.wantSHA {
				t.Fatalf("expected AppliedSHA %q, got %q", tc.wantSHA, s.AppliedSHA)
			}
			if s.ManagedUsers == nil || s.Files == nil || s.GeneratedUnits == nil || s.Secrets == nil || s.SecretSourcePaths == nil || s.Networks == nil {
				t.Fatalf("expected all maps and slices to be initialized, got %+v", s)
			}

			s.Files["/tmp/x"] = FileRecord{SHA256: "123", Scope: "rootful"}
			s.GeneratedUnits["rootful/x.service"] = "456"
			s.Secrets["rootful/s"] = "789"
			s.SecretSourcePaths["rootful/s"] = "secrets/s.age"
		})
	}
}

func TestLoadInvalidInputsReturnsError(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("expected error for empty path, got nil")
	}

	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("expected error decoding invalid JSON, got nil")
	}
}

func TestSaveAtomicAndLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var", "lib", "quadmatic")
	path := filepath.Join(dir, "state.json")

	want := &State{
		Version:      CurrentVersion,
		AppliedSHA:   "0123456789abcdef0123456789abcdef01234567",
		AppliedAt:    time.Date(2026, 11, 21, 21, 0, 0, 0, time.UTC),
		ManagedUsers: []string{"caddy", "open-webui"},
		Files: map[string]FileRecord{
			"/etc/containers/systemd/caddy.container": {
				SHA256:    "aaaa1111",
				Mode:      0o644,
				OwnerUID:  0,
				OwnerGID:  0,
				Component: "caddy",
				Scope:     "rootful",
				Kind:      "quadlet",
			},
			"/var/home/open-webui/.config/open-webui/config.toml": {
				SHA256:    "bbbb2222",
				Mode:      0o640,
				OwnerUID:  10001,
				OwnerGID:  10001,
				Component: "open-webui",
				Scope:     "open-webui",
				Kind:      "data",
			},
		},
		GeneratedUnits: map[string]string{
			"rootful/caddy.service":         "cccc3333",
			"open-webui/open-webui.service": "dddd4444",
		},
		Secrets: map[string]string{
			"open-webui/db_password": "eeee5555",
		},
		SecretSourcePaths: map[string]string{
			"open-webui/db_password": "secrets/db_password.age",
		},
		Networks: []ManagedNetworkRecord{
			{
				ConnectionName: "qm-open-webui",
				Kind:           "macvlan",
				Owned:          true,
				Component:      "open-webui",
				Scope:          "open-webui",
			},
			{
				ConnectionName: "qm-vlan-20",
				Kind:           "vlan",
				Owned:          true,
				Component:      "open-webui",
				Scope:          "host",
			},
		},
	}

	if err := SaveAtomic(path, want); err != nil {
		t.Fatalf("SaveAtomic failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved state file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file mode 0600, got %04o", perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved state file: %v", err)
	}
	if !strings.Contains(string(raw), "\n  \"") {
		t.Fatalf("expected indented JSON output, got:\n%s", string(raw))
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %q: %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("expected only state.json in %q, got %v", dir, entries)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}
}

func TestSaveAtomicOverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	first := NewEmpty()
	first.AppliedSHA = "1111111111111111111111111111111111111111"
	if err := SaveAtomic(path, first); err != nil {
		t.Fatalf("first SaveAtomic failed: %v", err)
	}

	second := NewEmpty()
	second.AppliedSHA = "2222222222222222222222222222222222222222"
	second.SecretSourcePaths["rootful/k"] = "secrets/k.age"
	if err := SaveAtomic(path, second); err != nil {
		t.Fatalf("second SaveAtomic failed: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !reflect.DeepEqual(got, second) {
		t.Fatalf("overwrite mismatch:\ngot:  %+v\nwant: %+v", got, second)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file mode 0600 after overwrite, got %04o", perm)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %q: %v", dir, err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file in %q, got %d", dir, len(entries))
	}
}

func TestSaveAtomicRejectsInvalidInputs(t *testing.T) {
	if err := SaveAtomic("", NewEmpty()); err == nil {
		t.Fatal("expected error for empty path")
	}

	validPath := filepath.Join(t.TempDir(), "state.json")
	if err := SaveAtomic(validPath, nil); err == nil {
		t.Fatal("expected error for nil state")
	}

	fileAsParent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileAsParent, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	if err := SaveAtomic(filepath.Join(fileAsParent, "state.json"), NewEmpty()); err == nil {
		t.Fatal("expected error when parent path is a regular file")
	}
}

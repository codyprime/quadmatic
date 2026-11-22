package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseConfigDefaultsAndOverrides(t *testing.T) {
	raw := []byte(`
repo_url = "git@git.example.lan:homelab/quadlets.git"
ssh_key = "/etc/quadmatic/deploy_key"
ssh_known_hosts = "/etc/quadmatic/known_hosts"
allowed_signers = "/etc/quadmatic/allowed-signers"
age_identity = "/etc/quadmatic/age.key"
trunk_interface = "enp3s0"
metrics_listen = "10.0.3.12:9100"
`)
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Branch != "main" {
		t.Fatalf("expected Branch %q, got %q", "main", cfg.Branch)
	}
	if cfg.PollInterval != 5*time.Minute {
		t.Fatalf("expected PollInterval %v, got %v", 5*time.Minute, cfg.PollInterval)
	}
	if cfg.StateFile != "/var/lib/quadmatic/state.json" {
		t.Fatalf("expected StateFile %q, got %q", "/var/lib/quadmatic/state.json", cfg.StateFile)
	}
	if cfg.RepoDir != "/var/lib/quadmatic/repo" {
		t.Fatalf("expected RepoDir %q, got %q", "/var/lib/quadmatic/repo", cfg.RepoDir)
	}
	if cfg.AllowNonFF {
		t.Fatalf("expected AllowNonFF false, got true")
	}
	if cfg.Hostname == "" {
		t.Fatalf("expected non-empty default Hostname")
	}
	if cfg.RepoURL != "git@git.example.lan:homelab/quadlets.git" {
		t.Fatalf("unexpected RepoURL: %q", cfg.RepoURL)
	}
	if cfg.AgeIdentity != "/etc/quadmatic/age.key" {
		t.Fatalf("unexpected AgeIdentity: %q", cfg.AgeIdentity)
	}
	if cfg.TrunkInterface != "enp3s0" {
		t.Fatalf("unexpected TrunkInterface: %q", cfg.TrunkInterface)
	}
	if cfg.MetricsListen != "10.0.3.12:9100" {
		t.Fatalf("unexpected MetricsListen: %q", cfg.MetricsListen)
	}

	overrideRaw := []byte(`
hostname = "fcos-node-01"
repo_url = "git@git.example.lan:homelab/quadlets.git"
branch = "prod"
poll_interval = "30s"
ssh_key = "/etc/quadmatic/deploy_key"
ssh_known_hosts = "/etc/quadmatic/known_hosts"
allowed_signers = "/etc/quadmatic/allowed-signers"
allow_non_ff = true
state_file = "/tmp/state.json"
repo_dir = "/tmp/repo"
`)
	overrideCfg, err := Parse(overrideRaw)
	if err != nil {
		t.Fatalf("Parse override failed: %v", err)
	}
	if overrideCfg.Hostname != "fcos-node-01" {
		t.Fatalf("expected Hostname %q, got %q", "fcos-node-01", overrideCfg.Hostname)
	}
	if overrideCfg.Branch != "prod" {
		t.Fatalf("expected Branch %q, got %q", "prod", overrideCfg.Branch)
	}
	if overrideCfg.PollInterval != 30*time.Second {
		t.Fatalf("expected PollInterval %v, got %v", 30*time.Second, overrideCfg.PollInterval)
	}
	if !overrideCfg.AllowNonFF {
		t.Fatalf("expected AllowNonFF true")
	}
	if overrideCfg.StateFile != "/tmp/state.json" {
		t.Fatalf("expected StateFile %q, got %q", "/tmp/state.json", overrideCfg.StateFile)
	}
	if overrideCfg.RepoDir != "/tmp/repo" {
		t.Fatalf("expected RepoDir %q, got %q", "/tmp/repo", overrideCfg.RepoDir)
	}
}

func TestValidateListenAddrRejectsWildcards(t *testing.T) {
	bad := []string{":9100", "0.0.0.0:9100", "[::]:9100", "[::ffff:0.0.0.0]:9100", "localhost:9100", "not-an-addr", "10.0.3.12:", "10.0.3.12:0", "10.0.3.12:abc"}
	for _, addr := range bad {
		if err := ValidateListenAddr(addr); err == nil {
			t.Fatalf("expected error for %q", addr)
		}
	}
	good := []string{"", "10.0.3.12:9100", "127.0.0.1:9100", "[fd00::1]:9100"}
	for _, addr := range good {
		if err := ValidateListenAddr(addr); err != nil {
			t.Fatalf("unexpected error for %q: %v", addr, err)
		}
	}
}

func TestParseConfigRejectsUnknownKeys(t *testing.T) {
	raw := []byte(`
repo_url = "git@git.example.lan:homelab/quadlets.git"
ssh_key = "/etc/quadmatic/deploy_key"
ssh_known_hosts = "/etc/quadmatic/known_hosts"
allowed_signers = "/etc/quadmatic/allowed-signers"
unknown_key = "oops"
`)
	if _, err := Parse(raw); err == nil {
		t.Fatalf("expected error for unknown config key")
	}
}

func TestParseConfigRejectsMissingRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "missing repo_url",
			raw: `
ssh_key = "/etc/quadmatic/deploy_key"
ssh_known_hosts = "/etc/quadmatic/known_hosts"
allowed_signers = "/etc/quadmatic/allowed-signers"
`,
		},
		{
			name: "missing ssh_key",
			raw: `
repo_url = "git@git.example.lan:homelab/quadlets.git"
ssh_known_hosts = "/etc/quadmatic/known_hosts"
allowed_signers = "/etc/quadmatic/allowed-signers"
`,
		},
		{
			name: "missing ssh_known_hosts",
			raw: `
repo_url = "git@git.example.lan:homelab/quadlets.git"
ssh_key = "/etc/quadmatic/deploy_key"
allowed_signers = "/etc/quadmatic/allowed-signers"
`,
		},
		{
			name: "missing allowed_signers",
			raw: `
repo_url = "git@git.example.lan:homelab/quadlets.git"
ssh_key = "/etc/quadmatic/deploy_key"
ssh_known_hosts = "/etc/quadmatic/known_hosts"
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.raw)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestParseConfigRejectsInvalidPollIntervalAndListenAddr(t *testing.T) {
	base := `
repo_url = "git@git.example.lan:homelab/quadlets.git"
ssh_key = "/etc/quadmatic/deploy_key"
ssh_known_hosts = "/etc/quadmatic/known_hosts"
allowed_signers = "/etc/quadmatic/allowed-signers"
`
	if _, err := Parse([]byte(base + `poll_interval = "not-a-duration"` + "\n")); err == nil {
		t.Fatalf("expected error for invalid poll_interval")
	}
	if _, err := Parse([]byte(base + `poll_interval = "-1s"` + "\n")); err == nil {
		t.Fatalf("expected error for non-positive poll_interval")
	}
	if _, err := Parse([]byte(base + `metrics_listen = "0.0.0.0:9100"` + "\n")); err == nil {
		t.Fatalf("expected error for wildcard metrics_listen")
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.toml")
	content := `
repo_url = "git@git.example.lan:homelab/quadlets.git"
ssh_key = "/etc/quadmatic/deploy_key"
ssh_known_hosts = "/etc/quadmatic/known_hosts"
allowed_signers = "/etc/quadmatic/allowed-signers"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Branch != "main" {
		t.Fatalf("expected Branch main, got %q", cfg.Branch)
	}

	if _, err := Load(filepath.Join(dir, "missing.toml")); err == nil {
		t.Fatalf("expected error loading nonexistent file")
	}
}

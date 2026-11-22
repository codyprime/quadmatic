package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	defaultBranch       = "main"
	defaultPollInterval = 5 * time.Minute
	defaultStateFile    = "/var/lib/quadmatic/state.json"
	defaultRepoDir      = "/var/lib/quadmatic/repo"
)

// HostConfig holds host-local daemon configuration loaded from host.toml.
type HostConfig struct {
	Hostname       string
	RepoURL        string
	Branch         string
	PollInterval   time.Duration
	SSHKey         string
	SSHKnownHosts  string
	AllowedSigners string
	AllowNonFF     bool
	AgeIdentity    string
	TrunkInterface string
	MetricsListen  string
	StateFile      string
	RepoDir        string
}

type rawHostConfig struct {
	Hostname       string `toml:"hostname"`
	RepoURL        string `toml:"repo_url"`
	Branch         string `toml:"branch"`
	PollInterval   string `toml:"poll_interval"`
	SSHKey         string `toml:"ssh_key"`
	SSHKnownHosts  string `toml:"ssh_known_hosts"`
	AllowedSigners string `toml:"allowed_signers"`
	AllowNonFF     bool   `toml:"allow_non_ff"`
	AgeIdentity    string `toml:"age_identity"`
	TrunkInterface string `toml:"trunk_interface"`
	MetricsListen  string `toml:"metrics_listen"`
	StateFile      string `toml:"state_file"`
	RepoDir        string `toml:"repo_dir"`
}

// Load reads and parses a HostConfig TOML file from path.
func Load(path string) (*HostConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes raw TOML bytes into a validated HostConfig with defaults applied.
func Parse(data []byte) (*HostConfig, error) {
	var raw rawHostConfig
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown config key(s): %s", strings.Join(keys, ", "))
	}

	pollInterval := defaultPollInterval
	if raw.PollInterval != "" {
		d, err := time.ParseDuration(raw.PollInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid poll_interval %q: %w", raw.PollInterval, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("poll_interval must be positive, got %s", d)
		}
		pollInterval = d
	}

	hostname := raw.Hostname
	if hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("determine hostname: %w", err)
		}
		if h == "" {
			return nil, fmt.Errorf("determine hostname: empty result")
		}
		hostname = h
	}

	cfg := &HostConfig{
		Hostname:       hostname,
		RepoURL:        raw.RepoURL,
		Branch:         defaultString(raw.Branch, defaultBranch),
		PollInterval:   pollInterval,
		SSHKey:         raw.SSHKey,
		SSHKnownHosts:  raw.SSHKnownHosts,
		AllowedSigners: raw.AllowedSigners,
		AllowNonFF:     raw.AllowNonFF,
		AgeIdentity:    raw.AgeIdentity,
		TrunkInterface: raw.TrunkInterface,
		MetricsListen:  raw.MetricsListen,
		StateFile:      defaultString(raw.StateFile, defaultStateFile),
		RepoDir:        defaultString(raw.RepoDir, defaultRepoDir),
	}

	required := []struct {
		name  string
		value string
	}{
		{"repo_url", cfg.RepoURL},
		{"ssh_key", cfg.SSHKey},
		{"ssh_known_hosts", cfg.SSHKnownHosts},
		{"allowed_signers", cfg.AllowedSigners},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return nil, fmt.Errorf("missing required config field %q", field.name)
		}
	}

	if err := ValidateListenAddr(cfg.MetricsListen); err != nil {
		return nil, fmt.Errorf("invalid metrics_listen: %w", err)
	}

	return cfg, nil
}

// ValidateListenAddr verifies that addr is either empty or an explicit IP:port
// without wildcard/unspecified addresses or DNS hostnames.
func ValidateListenAddr(addr string) error {
	if addr == "" {
		return nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("split host:port %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid port %q in %q", portStr, addr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("listen address host %q must be an explicit IP: %w", host, err)
	}
	if ip.Unmap().IsUnspecified() {
		return fmt.Errorf("listen address %q must not use an unspecified wildcard IP", addr)
	}
	return nil
}

func defaultString(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}

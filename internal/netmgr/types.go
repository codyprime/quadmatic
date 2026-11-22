package netmgr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"quadmatic/internal/state"
)

const (
	// ManagedPrefix is the connection/interface name prefix for quadmatic-owned VLAN and macvlan profiles.
	ManagedPrefix = "qm-"

	// ManagedVRFPrefix is the connection/interface name prefix for quadmatic-owned VRF profiles.
	ManagedVRFPrefix = "qmv-"

	// DefaultCgroupPattern is the default systemd cgroupv2 hierarchy pattern used for
	// nftables outbound_guard matching on rootless quadlet services.
	DefaultCgroupPattern = "user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{unit}"

	vrfTableOffset      = 10000
	vrfDefaultMetric    = "8192"
	maxIfNameLen        = 15
	tcpL3mdevAcceptPath = "/proc/sys/net/ipv4/tcp_l3mdev_accept"
	udpL3mdevAcceptPath = "/proc/sys/net/ipv4/udp_l3mdev_accept"
	defaultDHCPTimeout  = 30 * time.Second
	maxDHCPPollInterval = 250 * time.Millisecond
	minDHCPPollInterval = 10 * time.Millisecond
)

// Runner executes external networking commands (`nmcli`, `ip`, `nft`) with optional stdin.
type Runner interface {
	Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

// SysctlReader reads kernel sysctl values from procfs.
type SysctlReader interface {
	ReadSysctl(path string) (string, error)
}

// Snapshot captures pre-apply owned NetworkManager profiles and the live nftables table
// for transactional rollback.
type Snapshot struct {
	Profiles        map[string]string
	NFTablesRuleset string
	OwnedRecords    []state.ManagedNetworkRecord
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

type osSysctlReader struct{}

func (osSysctlReader) ReadSysctl(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Reconciler manages NetworkManager VLAN, VRF, and macvlan profiles plus the cgroupv2-scoped
// `inet quadmatic` nftables outbound guard.
type Reconciler struct {
	trunkInterface string
	runner         Runner
	sysctl         SysctlReader
	cgroupPattern  string
	// CgroupExists reports whether a cgroupv2 path currently exists on the host.
	// Defaults to checking that /sys/fs/cgroup/<cgPath> is a directory.
	CgroupExists func(cgPath string) bool
}

// NewReconciler constructs a Reconciler for trunkInterface using runner and sysctl
// (defaulting to os/exec and os.ReadFile when nil).
func NewReconciler(trunkInterface string, runner Runner, sysctl SysctlReader) *Reconciler {
	if runner == nil {
		runner = execRunner{}
	}
	if sysctl == nil {
		sysctl = osSysctlReader{}
	}
	return &Reconciler{
		trunkInterface: strings.TrimSpace(trunkInterface),
		runner:         runner,
		sysctl:         sysctl,
		cgroupPattern:  DefaultCgroupPattern,
		CgroupExists:   defaultCgroupExists,
	}
}

func defaultCgroupExists(cgPath string) bool {
	return CgroupExistsUnderRoot("/sys/fs/cgroup")(cgPath)
}

// CgroupExistsUnderRoot returns a CgroupExists predicate checking whether
// <root>/<cgPath> exists and is a directory.
func CgroupExistsUnderRoot(root string) func(string) bool {
	return func(cgPath string) bool {
		clean := strings.Trim(cgPath, "/")
		if clean == "" {
			return false
		}
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(clean)))
		return err == nil && info.IsDir()
	}
}

func (r *Reconciler) checkCgroupExists(cgPath string) bool {
	if r != nil && r.CgroupExists != nil {
		return r.CgroupExists(cgPath)
	}
	return defaultCgroupExists(cgPath)
}

// SetCgroupPattern overrides the cgroupv2 path pattern used by outbound_guard rules.
// Supported placeholders are {uid}, {unit}, {user}, and {component}.
func (r *Reconciler) SetCgroupPattern(pattern string) error {
	if r == nil {
		return errors.New("netmgr reconciler is nil")
	}
	trimmed := strings.Trim(strings.TrimSpace(pattern), "/")
	if trimmed == "" {
		return errors.New("cgroup pattern must not be empty")
	}
	if strings.ContainsAny(trimmed, "\x00\r\n\"\\") {
		return fmt.Errorf("cgroup pattern %q contains forbidden characters", pattern)
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("cgroup pattern %q contains invalid path segment %q", pattern, seg)
		}
	}
	r.cgroupPattern = trimmed
	return nil
}

// CheckKernelInvariants verifies that net.ipv4.tcp_l3mdev_accept and
// net.ipv4.udp_l3mdev_accept are both "0" so default-VRF sockets never accept
// connections arriving on VRF-enslaved untrusted VLANs.
func (r *Reconciler) CheckKernelInvariants() error {
	if r == nil {
		return errors.New("netmgr reconciler is nil")
	}
	sysctl := r.sysctl
	if sysctl == nil {
		sysctl = osSysctlReader{}
	}

	checks := []struct {
		path string
		name string
	}{
		{path: tcpL3mdevAcceptPath, name: "net.ipv4.tcp_l3mdev_accept"},
		{path: udpL3mdevAcceptPath, name: "net.ipv4.udp_l3mdev_accept"},
	}
	for _, c := range checks {
		raw, err := sysctl.ReadSysctl(c.path)
		if err != nil {
			return fmt.Errorf("read sysctl %s (%s): %w", c.name, c.path, err)
		}
		val := strings.TrimSpace(raw)
		if val != "0" {
			return fmt.Errorf("kernel invariant failed: %s (%s) = %q, must be \"0\"", c.name, c.path, val)
		}
	}
	return nil
}

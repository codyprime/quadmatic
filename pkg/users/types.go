package users

import (
	"context"
	"time"
)

// SubIDConfig configures deterministic subuid/subgid range calculation.
type SubIDConfig struct {
	Base    int `toml:"base"`
	UIDBase int `toml:"uid_base"`
	Count   int `toml:"count"`
}

// UserSpec declares a pinned-UID service user in users.toml.
type UserSpec struct {
	Name        string `toml:"-"`
	UID         int    `toml:"uid"`
	SubUIDStart int    `toml:"subuid_start"`
	SubUIDCount int    `toml:"subuid_count"`
}

// Registry represents the parsed fleet-wide users.toml registry.
type Registry struct {
	SubID SubIDConfig         `toml:"subid"`
	Users map[string]UserSpec `toml:"users"`
}

// ActionKind identifies an operation planned or performed by Reconciler.
type ActionKind string

const (
	CreateUser    ActionKind = "create_user"
	AdoptUser     ActionKind = "adopt_user"
	UpdateSubUID  ActionKind = "update_subuid"
	UpdateSubGID  ActionKind = "update_subgid"
	EnableLinger  ActionKind = "enable_linger"
	MigratePodman ActionKind = "migrate_podman"
)

// Action describes a single reconciliation step for a user.
type Action struct {
	Kind    ActionKind
	User    string
	UID     int
	Start   int
	Count   int
	Details string
}

// Plan holds the computed reconciliation actions and non-fatal warnings.
type Plan struct {
	Actions  []Action
	Warnings []string
}

// Runner executes external system commands.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Options configures paths, timeouts, and command execution for a Reconciler.
type Options struct {
	PasswdPath string
	SubUIDPath string
	SubGIDPath string
	LingerDir  string
	RunUserDir string
	HomeBase   string
	BusTimeout time.Duration
	Runner     Runner
}

// PasswdEntry represents a parsed line from /etc/passwd.
type PasswdEntry struct {
	Name  string
	UID   int
	GID   int
	GECOS string
	Home  string
	Shell string
}

// SubIDEntry represents a parsed line from /etc/subuid or /etc/subgid.
type SubIDEntry struct {
	Name  string
	Start int
	Count int
}

package users

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPasswdPath = "/etc/passwd"
	defaultSubUIDPath = "/etc/subuid"
	defaultSubGIDPath = "/etc/subgid"
	defaultLingerDir  = "/var/lib/systemd/linger"
	defaultRunUserDir = "/run/user"
	defaultHomeBase   = "/var/home"
	defaultBusTimeout = 15 * time.Second
	busPollInterval   = 25 * time.Millisecond
)

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Reconciler computes and applies pinned-UID user, subuid/subgid, and linger state.
type Reconciler struct {
	opts Options
}

// NewReconciler constructs a Reconciler with default OS paths and timeouts applied.
func NewReconciler(opts Options) *Reconciler {
	if opts.PasswdPath == "" {
		opts.PasswdPath = defaultPasswdPath
	}
	if opts.SubUIDPath == "" {
		opts.SubUIDPath = defaultSubUIDPath
	}
	if opts.SubGIDPath == "" {
		opts.SubGIDPath = defaultSubGIDPath
	}
	if opts.LingerDir == "" {
		opts.LingerDir = defaultLingerDir
	}
	if opts.RunUserDir == "" {
		opts.RunUserDir = defaultRunUserDir
	}
	if opts.HomeBase == "" {
		opts.HomeBase = defaultHomeBase
	}
	if opts.BusTimeout <= 0 {
		opts.BusTimeout = defaultBusTimeout
	}
	if opts.Runner == nil {
		opts.Runner = execRunner{}
	}
	return &Reconciler{opts: opts}
}

// Plan validates host state against reg and builds the non-mutating reconciliation plan.
func (r *Reconciler) Plan(ctx context.Context, reg *Registry, activeUsers []string, previouslyManaged []string) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if reg == nil {
		return nil, fmt.Errorf("users registry is nil")
	}

	sortedActive := dedupAndSort(activeUsers)
	activeSet := make(map[string]bool, len(sortedActive))
	for _, u := range sortedActive {
		if _, ok := reg.Users[u]; !ok {
			return nil, fmt.Errorf("active user %q not found in users registry", u)
		}
		activeSet[u] = true
	}

	plan := &Plan{}
	for _, prev := range dedupAndSort(previouslyManaged) {
		if !activeSet[prev] {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"previously managed user %q is no longer active; leaving account, home directory, and subid entries intact",
				prev,
			))
		}
	}

	passwdEntries, err := readPasswd(r.opts.PasswdPath)
	if err != nil {
		return nil, err
	}
	passwdByName := make(map[string]PasswdEntry, len(passwdEntries))
	passwdByUID := make(map[int]PasswdEntry, len(passwdEntries))
	for _, e := range passwdEntries {
		passwdByName[e.Name] = e
		passwdByUID[e.UID] = e
	}

	subuidEntries, err := readSubIDFile(r.opts.SubUIDPath)
	if err != nil {
		return nil, err
	}
	subgidEntries, err := readSubIDFile(r.opts.SubGIDPath)
	if err != nil {
		return nil, err
	}

	plannedTargets := make([]SubIDEntry, 0, len(sortedActive))

	for _, name := range sortedActive {
		spec := reg.Users[name]
		targetStart, targetCount := SubIDRange(spec.UID, spec, reg.SubID)
		targetSubID := SubIDEntry{Name: name, Start: targetStart, Count: targetCount}

		if err := CheckSubIDOverlap(subuidEntries, targetSubID); err != nil {
			return nil, fmt.Errorf("subuid validation for %q: %w", name, err)
		}
		if err := CheckSubIDOverlap(subgidEntries, targetSubID); err != nil {
			return nil, fmt.Errorf("subgid validation for %q: %w", name, err)
		}
		if err := CheckSubIDOverlap(plannedTargets, targetSubID); err != nil {
			return nil, fmt.Errorf("active users subid conflict for %q: %w", name, err)
		}
		plannedTargets = append(plannedTargets, targetSubID)

		_, existsOnHost := passwdByName[name]
		if existsOnHost {
			existing := passwdByName[name]
			if existing.UID != spec.UID {
				return nil, fmt.Errorf(
					"UID mismatch for user %q: host /etc/passwd has UID %d, registry pins UID %d",
					name, existing.UID, spec.UID,
				)
			}
			if !isNoLoginShell(existing.Shell) {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf(
					"adopted user %q has shell %q (expected nologin); leaving /etc/passwd untouched",
					name, existing.Shell,
				))
			}
			plan.Actions = append(plan.Actions, Action{
				Kind:    AdoptUser,
				User:    name,
				UID:     spec.UID,
				Details: fmt.Sprintf("adopt existing user %q (uid=%d)", name, spec.UID),
			})
		} else {
			if owner, conflict := passwdByUID[spec.UID]; conflict {
				return nil, fmt.Errorf(
					"UID %d for user %q is already assigned to existing host user %q",
					spec.UID, name, owner.Name,
				)
			}
			plan.Actions = append(plan.Actions, Action{
				Kind:    CreateUser,
				User:    name,
				UID:     spec.UID,
				Details: fmt.Sprintf("create user %q (uid=%d, home=%s)", name, spec.UID, filepath.Join(r.opts.HomeBase, name)),
			})
		}

		subuidChanged := !subIDMatches(subuidEntries, name, targetStart, targetCount)
		if subuidChanged {
			plan.Actions = append(plan.Actions, Action{
				Kind:    UpdateSubUID,
				User:    name,
				UID:     spec.UID,
				Start:   targetStart,
				Count:   targetCount,
				Details: fmt.Sprintf("set subuid %s:%d:%d", name, targetStart, targetCount),
			})
		}

		subgidChanged := !subIDMatches(subgidEntries, name, targetStart, targetCount)
		if subgidChanged {
			plan.Actions = append(plan.Actions, Action{
				Kind:    UpdateSubGID,
				User:    name,
				UID:     spec.UID,
				Start:   targetStart,
				Count:   targetCount,
				Details: fmt.Sprintf("set subgid %s:%d:%d", name, targetStart, targetCount),
			})
		}

		lingerPath := filepath.Join(r.opts.LingerDir, name)
		if _, err := os.Stat(lingerPath); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("stat linger file %q: %w", lingerPath, err)
			}
			plan.Actions = append(plan.Actions, Action{
				Kind:    EnableLinger,
				User:    name,
				UID:     spec.UID,
				Details: fmt.Sprintf("enable linger for %q (uid=%d)", name, spec.UID),
			})
		}

		if existsOnHost && (subuidChanged || subgidChanged) {
			plan.Actions = append(plan.Actions, Action{
				Kind:    MigratePodman,
				User:    name,
				UID:     spec.UID,
				Details: fmt.Sprintf("run podman system migrate for %q", name),
			})
		}
	}

	return plan, nil
}

// Apply computes a Plan and executes all planned user, subid, linger, and migration steps.
func (r *Reconciler) Apply(ctx context.Context, reg *Registry, activeUsers []string, previouslyManaged []string) (*Plan, error) {
	plan, err := r.Plan(ctx, reg, activeUsers, previouslyManaged)
	if err != nil {
		return nil, err
	}

	var subuidUpdates []SubIDEntry
	var subgidUpdates []SubIDEntry
	var lingerActions []Action
	var migrateActions []Action

	for _, act := range plan.Actions {
		switch act.Kind {
		case CreateUser:
			if err := r.createUser(ctx, act); err != nil {
				return plan, err
			}
		case AdoptUser:
			// Explicitly a no-op: never invoke usermod or mutate adopted user attributes.
		case UpdateSubUID:
			subuidUpdates = append(subuidUpdates, SubIDEntry{
				Name:  act.User,
				Start: act.Start,
				Count: act.Count,
			})
		case UpdateSubGID:
			subgidUpdates = append(subgidUpdates, SubIDEntry{
				Name:  act.User,
				Start: act.Start,
				Count: act.Count,
			})
		case EnableLinger:
			lingerActions = append(lingerActions, act)
		case MigratePodman:
			migrateActions = append(migrateActions, act)
		}
	}

	if len(subuidUpdates) > 0 {
		if err := applySubIDUpdatesAtomic(r.opts.SubUIDPath, subuidUpdates); err != nil {
			return plan, fmt.Errorf("update %s: %w", r.opts.SubUIDPath, err)
		}
	}
	if len(subgidUpdates) > 0 {
		if err := applySubIDUpdatesAtomic(r.opts.SubGIDPath, subgidUpdates); err != nil {
			return plan, fmt.Errorf("update %s: %w", r.opts.SubGIDPath, err)
		}
	}

	for _, act := range lingerActions {
		if err := r.enableLingerAndWait(ctx, act); err != nil {
			return plan, err
		}
	}

	for _, act := range migrateActions {
		if _, err := r.opts.Runner.Run(
			ctx,
			"systemd-run",
			"--machine="+act.User+"@.host",
			"--user",
			"--pipe",
			"--wait",
			"--quiet",
			"podman",
			"system",
			"migrate",
		); err != nil {
			return plan, fmt.Errorf("podman system migrate for %q: %w", act.User, err)
		}
	}

	return plan, nil
}

func (r *Reconciler) createUser(ctx context.Context, act Action) error {
	homeDir := filepath.Join(r.opts.HomeBase, act.User)
	if _, err := r.opts.Runner.Run(
		ctx,
		"useradd",
		"--uid", strconv.Itoa(act.UID),
		"--user-group",
		"--home-dir", homeDir,
		"--create-home",
		"--shell", "/usr/sbin/nologin",
		"--comment", "quadmatic managed user",
		act.User,
	); err != nil {
		return fmt.Errorf("create user %q: %w", act.User, err)
	}

	// Enforce 0700 on newly created user homes when the directory exists on disk.
	if _, err := os.Stat(homeDir); err == nil {
		if err := os.Chmod(homeDir, 0o700); err != nil {
			return fmt.Errorf("chmod home directory %q to 0700: %w", homeDir, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat home directory %q: %w", homeDir, err)
	}
	return nil
}

func (r *Reconciler) enableLingerAndWait(ctx context.Context, act Action) error {
	if _, err := r.opts.Runner.Run(ctx, "loginctl", "enable-linger", act.User); err != nil {
		return fmt.Errorf("enable linger for %q: %w", act.User, err)
	}
	busPath := filepath.Join(r.opts.RunUserDir, strconv.Itoa(act.UID), "bus")
	return r.waitForBus(ctx, act.User, busPath)
}

func (r *Reconciler) waitForBus(ctx context.Context, user, busPath string) error {
	if _, err := os.Stat(busPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat dbus socket %q: %w", busPath, err)
	}

	timer := time.NewTimer(r.opts.BusTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(busPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for user %q dbus socket at %s: %w", user, busPath, ctx.Err())
		case <-timer.C:
			return fmt.Errorf("timed out waiting for user %q dbus socket at %s after %s", user, busPath, r.opts.BusTimeout)
		case <-ticker.C:
			if _, err := os.Stat(busPath); err == nil {
				return nil
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("stat dbus socket %q: %w", busPath, err)
			}
		}
	}
}

func isNoLoginShell(shell string) bool {
	return shell == "/usr/sbin/nologin" || shell == "/sbin/nologin"
}

func dedupAndSort(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

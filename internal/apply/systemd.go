package apply

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// RootfulScope identifies the host system systemd / rootful Podman scope.
const RootfulScope = "rootful"

// UnitStatusInfo holds the systemd ActiveState, Type, and Result properties for a unit.
type UnitStatusInfo struct {
	ActiveState string
	Type        string
	Result      string
}

// Systemd abstracts systemd daemon and unit lifecycle operations across rootful
// and rootless user scopes.
type Systemd interface {
	DaemonReload(ctx context.Context, scope string) error
	Start(ctx context.Context, scope, unit string) error
	Stop(ctx context.Context, scope, unit string) error
	Restart(ctx context.Context, scope, unit string) error
	ActiveState(ctx context.Context, scope, unit string) (string, error)
	UnitState(ctx context.Context, scope, unit string) (UnitStatusInfo, error)
}

// CmdRunner executes external systemctl commands.
type CmdRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execCmdRunner struct{}

func (execCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// Systemctl implements Systemd by invoking `systemctl` for rootful scope and
// `systemctl --user -M <user>@` for rootless user scopes.
type Systemctl struct {
	runner CmdRunner
}

// NewSystemctl constructs a Systemctl backed by runner (defaulting to os/exec when nil).
func NewSystemctl(runner CmdRunner) *Systemctl {
	if runner == nil {
		runner = execCmdRunner{}
	}
	return &Systemctl{runner: runner}
}

// DaemonReload reloads systemd unit definitions for scope.
func (s *Systemctl) DaemonReload(ctx context.Context, scope string) error {
	if err := validateScope(scope); err != nil {
		return err
	}
	_, err := s.runSystemctl(ctx, scope, "daemon-reload")
	return err
}

// Start starts unit in scope.
func (s *Systemctl) Start(ctx context.Context, scope, unit string) error {
	if err := validateScopeAndUnit(scope, unit); err != nil {
		return err
	}
	_, err := s.runSystemctl(ctx, scope, "start", unit)
	return err
}

// Stop stops unit in scope. Exit status 5 (unit not loaded) is treated as a clean no-op.
func (s *Systemctl) Stop(ctx context.Context, scope, unit string) error {
	if err := validateScopeAndUnit(scope, unit); err != nil {
		return err
	}
	_, err := s.runSystemctl(ctx, scope, "stop", unit)
	if err != nil {
		var exitCoder interface{ ExitCode() int }
		if errors.As(err, &exitCoder) && exitCoder != nil && exitCoder.ExitCode() == 5 {
			return nil
		}
		return err
	}
	return nil
}

// Restart restarts unit in scope.
func (s *Systemctl) Restart(ctx context.Context, scope, unit string) error {
	if err := validateScopeAndUnit(scope, unit); err != nil {
		return err
	}
	_, err := s.runSystemctl(ctx, scope, "restart", unit)
	return err
}

// ActiveState returns systemd's ActiveState property for unit in scope.
func (s *Systemctl) ActiveState(ctx context.Context, scope, unit string) (string, error) {
	if err := validateScopeAndUnit(scope, unit); err != nil {
		return "", err
	}
	out, err := s.runSystemctl(ctx, scope, "show", "-p", "ActiveState", "--value", unit)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// UnitState returns systemd's ActiveState, Type, and Result properties for unit in scope.
func (s *Systemctl) UnitState(ctx context.Context, scope, unit string) (UnitStatusInfo, error) {
	if err := validateScopeAndUnit(scope, unit); err != nil {
		return UnitStatusInfo{}, err
	}
	out, err := s.runSystemctl(ctx, scope, "show", "-p", "ActiveState", "-p", "Type", "-p", "Result", unit)
	if err != nil {
		return UnitStatusInfo{}, err
	}
	return parseUnitStatusInfo(string(out)), nil
}

func parseUnitStatusInfo(raw string) UnitStatusInfo {
	var info UnitStatusInfo
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "ActiveState":
			info.ActiveState = strings.TrimSpace(v)
		case "Type":
			info.Type = strings.TrimSpace(v)
		case "Result":
			info.Result = strings.TrimSpace(v)
		}
	}
	return info
}

func (s *Systemctl) runSystemctl(ctx context.Context, scope string, opArgs ...string) ([]byte, error) {
	if s == nil {
		return nil, errors.New("systemctl client is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runner := s.runner
	if runner == nil {
		runner = execCmdRunner{}
	}

	args := buildSystemctlArgs(scope, opArgs...)
	out, err := runner.Run(ctx, "systemctl", args...)
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			return out, fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, detail)
		}
		return out, fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

func buildSystemctlArgs(scope string, opArgs ...string) []string {
	if scope == RootfulScope {
		return opArgs
	}
	args := make([]string, 0, 3+len(opArgs))
	args = append(args, "--user", "-M", scope+"@")
	args = append(args, opArgs...)
	return args
}

func validateScope(scope string) error {
	if scope == "" {
		return errors.New("systemd scope must not be empty")
	}
	if strings.HasPrefix(scope, "-") || strings.ContainsAny(scope, " \t\r\n/\\@\x00") {
		return fmt.Errorf("invalid systemd scope %q", scope)
	}
	return nil
}

func validateUnit(unit string) error {
	if unit == "" {
		return errors.New("systemd unit must not be empty")
	}
	if strings.HasPrefix(unit, "-") || strings.ContainsAny(unit, " \t\r\n/\\\x00") {
		return fmt.Errorf("invalid systemd unit %q", unit)
	}
	return nil
}

func validateScopeAndUnit(scope, unit string) error {
	if err := validateScope(scope); err != nil {
		return err
	}
	return validateUnit(unit)
}

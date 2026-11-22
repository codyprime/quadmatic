package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const rootfulScope = "rootful"

// ExecRunner executes an external command, piping stdin without exposing it in argv.
type ExecRunner interface {
	RunWithStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) RunWithStdin(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// Manager creates, replaces, and removes Podman secrets in rootful or rootless scopes.
type Manager struct {
	runner ExecRunner
}

// NewManager constructs a Manager using runner (defaulting to os/exec when nil).
func NewManager(runner ExecRunner) *Manager {
	if runner == nil {
		runner = execRunner{}
	}
	return &Manager{runner: runner}
}

// Upsert creates or replaces the named Podman secret in scope, piping plaintext
// strictly over stdin and never via CLI arguments, files, or error messages.
func (m *Manager) Upsert(ctx context.Context, scope, name string, plaintext []byte) error {
	if m == nil {
		return errors.New("secrets manager is nil")
	}
	if err := validateIdentifier("scope", scope); err != nil {
		return err
	}
	if err := validateIdentifier("secret name", name); err != nil {
		return err
	}
	return m.runPodman(ctx, scope, "upsert", name, plaintext, "secret", "create", "--replace", name, "-")
}

// Remove deletes the named Podman secret from scope (ignoring missing secrets).
func (m *Manager) Remove(ctx context.Context, scope, name string) error {
	if m == nil {
		return errors.New("secrets manager is nil")
	}
	if err := validateIdentifier("scope", scope); err != nil {
		return err
	}
	if err := validateIdentifier("secret name", name); err != nil {
		return err
	}
	return m.runPodman(ctx, scope, "remove", name, nil, "secret", "rm", "--ignore", name)
}

func (m *Manager) runPodman(ctx context.Context, scope, op, secretName string, stdin []byte, podmanArgs ...string) error {
	runner := m.runner
	if runner == nil {
		runner = execRunner{}
	}

	var (
		bin  string
		args []string
	)
	if scope == rootfulScope {
		bin = "podman"
		args = podmanArgs
	} else {
		bin = "systemd-run"
		args = make([]string, 0, 6+len(podmanArgs))
		args = append(args,
			"--machine="+scope+"@.host",
			"--user",
			"--pipe",
			"--wait",
			"--quiet",
			"podman",
		)
		args = append(args, podmanArgs...)
	}

	out, err := runner.RunWithStdin(ctx, stdin, bin, args...)
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			return fmt.Errorf("podman secret %s for scope %q secret %q: %w: %s", op, scope, secretName, err, detail)
		}
		return fmt.Errorf("podman secret %s for scope %q secret %q: %w", op, scope, secretName, err)
	}
	return nil
}

func validateIdentifier(kind, val string) error {
	if val == "" {
		return fmt.Errorf("%s must not be empty", kind)
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum && c != '_' {
				return fmt.Errorf("invalid %s %q: must start with an alphanumeric character or underscore", kind, val)
			}
			continue
		}
		if !isAlphaNum && c != '_' && c != '.' && c != '-' {
			return fmt.Errorf("invalid %s %q: contains disallowed character %q", kind, val, c)
		}
	}
	return nil
}

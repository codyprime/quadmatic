package users_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"quadmatic/pkg/users"
)

type recordedCall struct {
	Name string
	Args []string
}

type fakeRunner struct {
	calls []recordedCall
	hook  func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cp := append([]string(nil), args...)
	f.calls = append(f.calls, recordedCall{Name: name, Args: cp})
	if f.hook != nil {
		return f.hook(ctx, name, args...)
	}
	return nil, nil
}

func TestParseRegistryFormulaAndOverrides(t *testing.T) {
	t.Run("formula defaults and explicit overrides", func(t *testing.T) {
		tomlData := `
[users.openwebui]
uid = 2001

[users.legacy_app]
uid = 1005
subuid_start = 100000
subuid_count = 65536
`
		reg, err := users.ParseRegistry([]byte(tomlData))
		if err != nil {
			t.Fatalf("ParseRegistry returned unexpected error: %v", err)
		}

		if reg.SubID.Base != 1_000_000 || reg.SubID.UIDBase != 2000 || reg.SubID.Count != 65536 {
			t.Fatalf("unexpected SubID defaults: %+v", reg.SubID)
		}

		start, count := users.SubIDRange(2001, reg.Users["openwebui"], reg.SubID)
		if start != 1065536 || count != 65536 {
			t.Fatalf("expected (1065536, 65536) for UID 2001, got (%d, %d)", start, count)
		}

		legacyStart, legacyCount := users.SubIDRange(1005, reg.Users["legacy_app"], reg.SubID)
		if legacyStart != 100000 || legacyCount != 65536 {
			t.Fatalf("expected (100000, 65536) for override, got (%d, %d)", legacyStart, legacyCount)
		}
	})

	t.Run("rejects duplicate UID", func(t *testing.T) {
		tomlData := `
[users.a]
uid = 2001

[users.b]
uid = 2001
`
		if _, err := users.ParseRegistry([]byte(tomlData)); err == nil {
			t.Fatal("expected error for duplicate UID, got nil")
		}
	})

	t.Run("rejects UID below 1000", func(t *testing.T) {
		tomlData := `
[users.sys]
uid = 999
`
		if _, err := users.ParseRegistry([]byte(tomlData)); err == nil {
			t.Fatal("expected error for UID < 1000, got nil")
		}
	})

	t.Run("rejects overlapping ranges within registry", func(t *testing.T) {
		tomlData := `
[users.a]
uid = 2001

[users.b]
uid = 2002
subuid_start = 1065536
subuid_count = 65536
`
		if _, err := users.ParseRegistry([]byte(tomlData)); err == nil {
			t.Fatal("expected error for overlapping ranges in registry, got nil")
		}
	})

	t.Run("rejects invalid username and unknown keys", func(t *testing.T) {
		if _, err := users.ParseRegistry([]byte("[users.BadUser]\nuid = 2001\n")); err == nil {
			t.Fatal("expected error for invalid username, got nil")
		}
		if _, err := users.ParseRegistry([]byte("extra = true\n[users.good]\nuid = 2001\n")); err == nil {
			t.Fatal("expected error for unknown key, got nil")
		}
	})

	t.Run("LoadRegistry from file", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "users.toml")
		if err := os.WriteFile(p, []byte("[users.caddy]\nuid = 2002\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		reg, err := users.LoadRegistry(p)
		if err != nil {
			t.Fatalf("LoadRegistry failed: %v", err)
		}
		if reg.Users["caddy"].UID != 2002 {
			t.Fatalf("expected UID 2002, got %d", reg.Users["caddy"].UID)
		}
	})
}

func TestPlanRejectsExistingSubIDOverlap(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")
	lingerDir := filepath.Join(dir, "linger")
	runUserDir := filepath.Join(dir, "run_user")
	homeBase := filepath.Join(dir, "home")

	mustWriteFile(t, passwdPath, "core:x:1000:1000:CoreOS user:/var/home/core:/bin/bash\n")
	mustWriteFile(t, subuidPath, "core:100000:65536\n")
	mustWriteFile(t, subgidPath, "core:100000:65536\n")

	reg, err := users.ParseRegistry([]byte(`
[users.app]
uid = 2001
subuid_start = 130000
subuid_count = 65536
`))
	if err != nil {
		t.Fatalf("ParseRegistry failed: %v", err)
	}

	runner := &fakeRunner{}
	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  lingerDir,
		RunUserDir: runUserDir,
		HomeBase:   homeBase,
		BusTimeout: 200 * time.Millisecond,
		Runner:     runner,
	})

	_, err = rec.Plan(context.Background(), reg, []string{"app"}, nil)
	if err == nil {
		t.Fatal("expected Plan to reject overlapping subuid range, got nil")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("expected overlap error message, got: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected zero runner calls on failed Plan, got %+v", runner.calls)
	}
	if got := mustReadFile(t, subuidPath); got != "core:100000:65536\n" {
		t.Fatalf("subuid mutated on failed Plan: %q", got)
	}
}

func TestPlanAndApplyCreateUser(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")
	lingerDir := filepath.Join(dir, "linger")
	runUserDir := filepath.Join(dir, "run_user")
	homeBase := filepath.Join(dir, "home")

	mustMkdirAll(t, lingerDir)
	mustMkdirAll(t, runUserDir)
	mustMkdirAll(t, homeBase)
	mustWriteFile(t, passwdPath, "core:x:1000:1000:CoreOS:/var/home/core:/bin/bash\n")
	mustWriteFile(t, subuidPath, "core:100000:65536\n")
	mustWriteFile(t, subgidPath, "core:100000:65536\n")

	reg, err := users.ParseRegistry([]byte(`
[users.openwebui]
uid = 2001
`))
	if err != nil {
		t.Fatalf("ParseRegistry failed: %v", err)
	}

	runner := &fakeRunner{
		hook: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "useradd" {
				// Simulate useradd creating the home directory with permissive mode so
				// reconciler must enforce 0700.
				home := filepath.Join(homeBase, "openwebui")
				if err := os.MkdirAll(home, 0o755); err != nil {
					return nil, err
				}
				if err := os.Chmod(home, 0o755); err != nil {
					return nil, err
				}
			}
			if name == "loginctl" && len(args) >= 2 && args[0] == "enable-linger" && args[1] == "openwebui" {
				if err := os.WriteFile(filepath.Join(lingerDir, "openwebui"), nil, 0o644); err != nil {
					return nil, err
				}
				// Simulate delayed bus readiness to exercise polling.
				go func() {
					time.Sleep(30 * time.Millisecond)
					busDir := filepath.Join(runUserDir, "2001")
					_ = os.MkdirAll(busDir, 0o700)
					_ = os.WriteFile(filepath.Join(busDir, "bus"), nil, 0o600)
				}()
			}
			return nil, nil
		},
	}

	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  lingerDir,
		RunUserDir: runUserDir,
		HomeBase:   homeBase,
		BusTimeout: 1 * time.Second,
		Runner:     runner,
	})

	plan, err := rec.Apply(context.Background(), reg, []string{"openwebui"}, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	wantKinds := []users.ActionKind{
		users.CreateUser,
		users.UpdateSubUID,
		users.UpdateSubGID,
		users.EnableLinger,
	}
	var gotKinds []users.ActionKind
	for _, a := range plan.Actions {
		gotKinds = append(gotKinds, a.Kind)
	}
	if !slices.Equal(gotKinds, wantKinds) {
		t.Fatalf("unexpected action kinds: got %v, want %v", gotKinds, wantKinds)
	}

	expectedUseraddArgs := []string{
		"--uid", "2001",
		"--user-group",
		"--home-dir", filepath.Join(homeBase, "openwebui"),
		"--create-home",
		"--shell", "/usr/sbin/nologin",
		"--comment", "quadmatic managed user",
		"openwebui",
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 runner calls (useradd + loginctl), got %d: %+v", len(runner.calls), runner.calls)
	}
	if runner.calls[0].Name != "useradd" || !slices.Equal(runner.calls[0].Args, expectedUseraddArgs) {
		t.Fatalf("unexpected useradd call: %+v (want args %v)", runner.calls[0], expectedUseraddArgs)
	}
	if runner.calls[1].Name != "loginctl" || !slices.Equal(runner.calls[1].Args, []string{"enable-linger", "openwebui"}) {
		t.Fatalf("unexpected loginctl call: %+v", runner.calls[1])
	}

	info, err := os.Stat(filepath.Join(homeBase, "openwebui"))
	if err != nil {
		t.Fatalf("stat home dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("expected home dir mode 0700, got %04o", perm)
	}

	subuid := mustReadFile(t, subuidPath)
	if !strings.Contains(subuid, "core:100000:65536\n") || !strings.Contains(subuid, "openwebui:1065536:65536\n") {
		t.Fatalf("unexpected subuid contents:\n%s", subuid)
	}
	subgid := mustReadFile(t, subgidPath)
	if !strings.Contains(subgid, "core:100000:65536\n") || !strings.Contains(subgid, "openwebui:1065536:65536\n") {
		t.Fatalf("unexpected subgid contents:\n%s", subgid)
	}
}

func TestAdoptExistingUserNeverCallsUsermod(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")
	lingerDir := filepath.Join(dir, "linger")
	runUserDir := filepath.Join(dir, "run_user")
	homeBase := filepath.Join(dir, "home")

	mustMkdirAll(t, lingerDir)
	mustMkdirAll(t, filepath.Join(homeBase, "openwebui"))
	if err := os.Chmod(filepath.Join(homeBase, "openwebui"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustMkdirAll(t, filepath.Join(runUserDir, "2001"))
	mustWriteFile(t, filepath.Join(runUserDir, "2001", "bus"), "")

	// Pre-existing user without quadmatic comment and with /bin/bash shell, plus old subuid/subgid range.
	mustWriteFile(t, passwdPath, "core:x:1000:1000::/var/home/core:/bin/bash\nopenwebui:x:2001:2001::/var/home/openwebui:/bin/bash\n")
	mustWriteFile(t, subuidPath, "core:100000:65536\nopenwebui:200000:65536\n")
	mustWriteFile(t, subgidPath, "core:100000:65536\nopenwebui:200000:65536\n")

	reg, err := users.ParseRegistry([]byte(`
[users.openwebui]
uid = 2001
`))
	if err != nil {
		t.Fatalf("ParseRegistry failed: %v", err)
	}

	runner := &fakeRunner{}
	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  lingerDir,
		RunUserDir: runUserDir,
		HomeBase:   homeBase,
		BusTimeout: 500 * time.Millisecond,
		Runner:     runner,
	})

	plan, err := rec.Apply(context.Background(), reg, []string{"openwebui"}, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if len(plan.Warnings) == 0 {
		t.Fatal("expected warning about non-nologin shell on adopted user")
	}
	foundShellWarn := false
	for _, w := range plan.Warnings {
		if strings.Contains(w, "/bin/bash") && strings.Contains(w, "openwebui") {
			foundShellWarn = true
		}
	}
	if !foundShellWarn {
		t.Fatalf("expected non-nologin shell warning, got %v", plan.Warnings)
	}

	wantKinds := []users.ActionKind{
		users.AdoptUser,
		users.UpdateSubUID,
		users.UpdateSubGID,
		users.EnableLinger,
		users.MigratePodman,
	}
	var gotKinds []users.ActionKind
	for _, a := range plan.Actions {
		gotKinds = append(gotKinds, a.Kind)
	}
	if !slices.Equal(gotKinds, wantKinds) {
		t.Fatalf("unexpected action kinds: got %v, want %v", gotKinds, wantKinds)
	}

	for _, c := range runner.calls {
		if c.Name == "usermod" || c.Name == "useradd" {
			t.Fatalf("unexpected user mutation command %q called on adopted user: %+v", c.Name, c)
		}
	}

	// Verify podman system migrate was called as openwebui via systemd-run.
	foundMigrate := false
	for _, c := range runner.calls {
		if c.Name == "systemd-run" && slices.Contains(c.Args, "podman") && slices.Contains(c.Args, "migrate") && slices.Contains(c.Args, "--machine=openwebui@.host") {
			foundMigrate = true
		}
	}
	if !foundMigrate {
		t.Fatalf("expected podman system migrate call as openwebui, got calls: %+v", runner.calls)
	}

	// Adopted home directory permissions must NOT be mutated.
	info, err := os.Stat(filepath.Join(homeBase, "openwebui"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Fatalf("expected adopted home dir mode to remain 0755, got %04o", perm)
	}

	subuid := mustReadFile(t, subuidPath)
	if strings.Contains(subuid, "200000") || !strings.Contains(subuid, "openwebui:1065536:65536\n") || !strings.Contains(subuid, "core:100000:65536\n") {
		t.Fatalf("unexpected subuid after adoption:\n%s", subuid)
	}
}

func TestAdoptRejectsUIDMismatch(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")

	mustWriteFile(t, passwdPath, "openwebui:x:1005:1005::/var/home/openwebui:/usr/sbin/nologin\n")
	mustWriteFile(t, subuidPath, "")
	mustWriteFile(t, subgidPath, "")

	reg, err := users.ParseRegistry([]byte(`
[users.openwebui]
uid = 2001
`))
	if err != nil {
		t.Fatalf("ParseRegistry failed: %v", err)
	}

	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  filepath.Join(dir, "linger"),
		RunUserDir: filepath.Join(dir, "run_user"),
		HomeBase:   filepath.Join(dir, "home"),
		Runner:     &fakeRunner{},
	})

	_, err = rec.Plan(context.Background(), reg, []string{"openwebui"}, nil)
	if err == nil {
		t.Fatal("expected Plan to reject UID mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "1005") || !strings.Contains(err.Error(), "2001") {
		t.Fatalf("expected UID mismatch details (1005 vs 2001), got: %v", err)
	}
}

func TestDecommissionedUserProducesWarningNeverDeletes(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")
	lingerDir := filepath.Join(dir, "linger")
	runUserDir := filepath.Join(dir, "run_user")

	mustMkdirAll(t, lingerDir)
	mustWriteFile(t, filepath.Join(lingerDir, "openwebui"), "")
	mustWriteFile(t, passwdPath, "openwebui:x:2001:2001:quadmatic managed user:/var/home/openwebui:/usr/sbin/nologin\noldsvc:x:2002:2002:quadmatic managed user:/var/home/oldsvc:/usr/sbin/nologin\n")
	mustWriteFile(t, subuidPath, "openwebui:1065536:65536\noldsvc:1131072:65536\n")
	mustWriteFile(t, subgidPath, "openwebui:1065536:65536\noldsvc:1131072:65536\n")

	reg, err := users.ParseRegistry([]byte(`
[users.openwebui]
uid = 2001

[users.oldsvc]
uid = 2002
`))
	if err != nil {
		t.Fatalf("ParseRegistry failed: %v", err)
	}

	runner := &fakeRunner{}
	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  lingerDir,
		RunUserDir: runUserDir,
		HomeBase:   filepath.Join(dir, "home"),
		Runner:     runner,
	})

	plan, err := rec.Apply(context.Background(), reg, []string{"openwebui"}, []string{"openwebui", "oldsvc"})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	if len(plan.Warnings) == 0 {
		t.Fatal("expected warning for decommissioned user oldsvc")
	}
	foundWarn := false
	for _, w := range plan.Warnings {
		if strings.Contains(w, "oldsvc") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected warning mentioning oldsvc, got %v", plan.Warnings)
	}

	for _, c := range runner.calls {
		if c.Name == "userdel" {
			t.Fatalf("userdel must never be called: %+v", c)
		}
	}
	if got := mustReadFile(t, subuidPath); !strings.Contains(got, "oldsvc:1131072:65536") {
		t.Fatalf("subuid entry for decommissioned user must not be deleted:\n%s", got)
	}
}

func TestApplyBusTimeoutReturnsError(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")
	lingerDir := filepath.Join(dir, "linger")
	runUserDir := filepath.Join(dir, "run_user")

	mustMkdirAll(t, lingerDir)
	mustMkdirAll(t, runUserDir)
	mustWriteFile(t, passwdPath, "openwebui:x:2001:2001::/var/home/openwebui:/usr/sbin/nologin\n")
	mustWriteFile(t, subuidPath, "openwebui:1065536:65536\n")
	mustWriteFile(t, subgidPath, "openwebui:1065536:65536\n")

	reg, err := users.ParseRegistry([]byte("[users.openwebui]\nuid = 2001\n"))
	if err != nil {
		t.Fatal(err)
	}

	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  lingerDir,
		RunUserDir: runUserDir,
		HomeBase:   filepath.Join(dir, "home"),
		BusTimeout: 60 * time.Millisecond,
		Runner:     &fakeRunner{},
	})

	_, err = rec.Apply(context.Background(), reg, []string{"openwebui"}, nil)
	if err == nil {
		t.Fatal("expected bus timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "bus") {
		t.Fatalf("expected error mentioning bus timeout, got: %v", err)
	}
}

func TestPlanRejectsHostUIDConflict(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")

	mustWriteFile(t, passwdPath, "otheruser:x:2001:2001::/var/home/otheruser:/bin/bash\n")
	mustWriteFile(t, subuidPath, "")
	mustWriteFile(t, subgidPath, "")

	reg, err := users.ParseRegistry([]byte("[users.openwebui]\nuid = 2001\n"))
	if err != nil {
		t.Fatal(err)
	}

	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  filepath.Join(dir, "linger"),
		RunUserDir: filepath.Join(dir, "run_user"),
		HomeBase:   filepath.Join(dir, "home"),
		Runner:     &fakeRunner{},
	})

	_, err = rec.Plan(context.Background(), reg, []string{"openwebui"}, nil)
	if err == nil {
		t.Fatal("expected Plan to reject host UID conflict, got nil")
	}
	if !strings.Contains(err.Error(), "otheruser") || !strings.Contains(err.Error(), "2001") {
		t.Fatalf("expected UID conflict details mentioning otheruser and 2001, got: %v", err)
	}
}

func TestApplyIsIdempotentForConvergedUser(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")
	lingerDir := filepath.Join(dir, "linger")

	mustMkdirAll(t, lingerDir)
	mustWriteFile(t, filepath.Join(lingerDir, "openwebui"), "")
	mustWriteFile(t, passwdPath, "openwebui:x:2001:2001:quadmatic managed user:/var/home/openwebui:/usr/sbin/nologin\n")
	mustWriteFile(t, subuidPath, "openwebui:1065536:65536\n")
	mustWriteFile(t, subgidPath, "openwebui:1065536:65536\n")

	reg, err := users.ParseRegistry([]byte("[users.openwebui]\nuid = 2001\n"))
	if err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{}
	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  lingerDir,
		RunUserDir: filepath.Join(dir, "run_user"),
		HomeBase:   filepath.Join(dir, "home"),
		Runner:     runner,
	})

	plan, err := rec.Apply(context.Background(), reg, []string{"openwebui"}, nil)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(plan.Warnings) != 0 {
		t.Fatalf("expected zero warnings, got %v", plan.Warnings)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != users.AdoptUser {
		t.Fatalf("expected only AdoptUser action for converged user, got %+v", plan.Actions)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected zero runner calls for converged user, got %+v", runner.calls)
	}
}

func TestApplyReplacesUseraddAutoSubID(t *testing.T) {
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	subuidPath := filepath.Join(dir, "subuid")
	subgidPath := filepath.Join(dir, "subgid")
	lingerDir := filepath.Join(dir, "linger")
	runUserDir := filepath.Join(dir, "run_user")
	homeBase := filepath.Join(dir, "home")

	mustMkdirAll(t, lingerDir)
	mustMkdirAll(t, filepath.Join(runUserDir, "2001"))
	mustWriteFile(t, filepath.Join(runUserDir, "2001", "bus"), "")
	mustWriteFile(t, passwdPath, "core:x:1000:1000::/var/home/core:/bin/bash\n")
	mustWriteFile(t, subuidPath, "core:100000:65536\n")
	mustWriteFile(t, subgidPath, "core:100000:65536\n")

	reg, err := users.ParseRegistry([]byte("[users.openwebui]\nuid = 2001\n"))
	if err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{
		hook: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "useradd" {
				// Simulate useradd automatically appending a shadow-utils default subid line.
				f, err := os.OpenFile(subuidPath, os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					return nil, err
				}
				_, _ = f.WriteString("openwebui:165536:65536\n")
				_ = f.Close()

				g, err := os.OpenFile(subgidPath, os.O_APPEND|os.O_WRONLY, 0o644)
				if err != nil {
					return nil, err
				}
				_, _ = g.WriteString("openwebui:165536:65536\n")
				_ = g.Close()
			}
			return nil, nil
		},
	}

	rec := users.NewReconciler(users.Options{
		PasswdPath: passwdPath,
		SubUIDPath: subuidPath,
		SubGIDPath: subgidPath,
		LingerDir:  lingerDir,
		RunUserDir: runUserDir,
		HomeBase:   homeBase,
		BusTimeout: 200 * time.Millisecond,
		Runner:     runner,
	})

	if _, err := rec.Apply(context.Background(), reg, []string{"openwebui"}, nil); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	want := "core:100000:65536\nopenwebui:1065536:65536\n"
	if got := mustReadFile(t, subuidPath); got != want {
		t.Fatalf("subuid mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if got := mustReadFile(t, subgidPath); got != want {
		t.Fatalf("subgid mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestApplyBatchSubIDUpdateIgnoresPreUpdateEntriesOfUpdatedUsers(t *testing.T) {
	t.Run("two new users where useradd auto-allocates colliding range", func(t *testing.T) {
		dir := t.TempDir()
		passwdPath := filepath.Join(dir, "passwd")
		subuidPath := filepath.Join(dir, "subuid")
		subgidPath := filepath.Join(dir, "subgid")
		lingerDir := filepath.Join(dir, "linger")
		runUserDir := filepath.Join(dir, "run_user")

		mustMkdirAll(t, lingerDir)
		mustMkdirAll(t, filepath.Join(runUserDir, "2001"))
		mustMkdirAll(t, filepath.Join(runUserDir, "2002"))
		mustWriteFile(t, filepath.Join(runUserDir, "2001", "bus"), "")
		mustWriteFile(t, filepath.Join(runUserDir, "2002", "bus"), "")
		mustWriteFile(t, passwdPath, "core:x:1000:1000::/var/home/core:/bin/bash\n")
		mustWriteFile(t, subuidPath, "core:100000:65536\n")
		mustWriteFile(t, subgidPath, "core:100000:65536\n")

		reg, err := users.ParseRegistry([]byte(`
[users.alpha]
uid = 2001

[users.beta]
uid = 2002
`))
		if err != nil {
			t.Fatal(err)
		}

		runner := &fakeRunner{
			hook: func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if name == "useradd" {
					user := args[len(args)-1]
					if user == "alpha" {
						// Auto-allocated range collides with beta's target range (1131072:65536).
						for _, p := range []string{subuidPath, subgidPath} {
							f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
							if err != nil {
								return nil, err
							}
							_, _ = f.WriteString("alpha:1131072:65536\n")
							_ = f.Close()
						}
					}
				}
				return nil, nil
			},
		}

		rec := users.NewReconciler(users.Options{
			PasswdPath: passwdPath,
			SubUIDPath: subuidPath,
			SubGIDPath: subgidPath,
			LingerDir:  lingerDir,
			RunUserDir: runUserDir,
			HomeBase:   filepath.Join(dir, "home"),
			BusTimeout: 200 * time.Millisecond,
			Runner:     runner,
		})

		if _, err := rec.Apply(context.Background(), reg, []string{"alpha", "beta"}, nil); err != nil {
			t.Fatalf("Apply failed on batch update: %v", err)
		}

		want := "core:100000:65536\nalpha:1065536:65536\nbeta:1131072:65536\n"
		if got := mustReadFile(t, subuidPath); got != want {
			t.Fatalf("subuid mismatch:\ngot:\n%s\nwant:\n%s", got, want)
		}
		if got := mustReadFile(t, subgidPath); got != want {
			t.Fatalf("subgid mismatch:\ngot:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("two adopted users shifting into each others prior ranges", func(t *testing.T) {
		dir := t.TempDir()
		passwdPath := filepath.Join(dir, "passwd")
		subuidPath := filepath.Join(dir, "subuid")
		subgidPath := filepath.Join(dir, "subgid")
		lingerDir := filepath.Join(dir, "linger")

		mustMkdirAll(t, lingerDir)
		mustWriteFile(t, filepath.Join(lingerDir, "alpha"), "")
		mustWriteFile(t, filepath.Join(lingerDir, "beta"), "")
		mustWriteFile(t, passwdPath, "alpha:x:2001:2001::/var/home/alpha:/usr/sbin/nologin\nbeta:x:2002:2002::/var/home/beta:/usr/sbin/nologin\n")
		mustWriteFile(t, subuidPath, "alpha:1131072:65536\nbeta:1065536:65536\n")
		mustWriteFile(t, subgidPath, "alpha:1131072:65536\nbeta:1065536:65536\n")

		reg, err := users.ParseRegistry([]byte(`
[users.alpha]
uid = 2001

[users.beta]
uid = 2002
`))
		if err != nil {
			t.Fatal(err)
		}

		rec := users.NewReconciler(users.Options{
			PasswdPath: passwdPath,
			SubUIDPath: subuidPath,
			SubGIDPath: subgidPath,
			LingerDir:  lingerDir,
			RunUserDir: filepath.Join(dir, "run_user"),
			HomeBase:   filepath.Join(dir, "home"),
			BusTimeout: 200 * time.Millisecond,
			Runner:     &fakeRunner{},
		})

		if _, err := rec.Apply(context.Background(), reg, []string{"alpha", "beta"}, nil); err != nil {
			t.Fatalf("Apply failed on swapped adopted ranges: %v", err)
		}

		want := "alpha:1065536:65536\nbeta:1131072:65536\n"
		if got := mustReadFile(t, subuidPath); got != want {
			t.Fatalf("subuid mismatch:\ngot:\n%s\nwant:\n%s", got, want)
		}
		if got := mustReadFile(t, subgidPath); got != want {
			t.Fatalf("subgid mismatch:\ngot:\n%s\nwant:\n%s", got, want)
		}
	})
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

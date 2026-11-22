package apply

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"quadmatic/internal/manifest"
)

func TestFormatPlanSummaryNotesPlaceholderTrunk(t *testing.T) {
	rendered := &manifest.RenderedHost{
		Hostname:             "services-02",
		UsedPlaceholderTrunk: true,
	}
	summary := formatPlanSummary("sha1", "sha2", rendered, nil, &applyPlan{}, false, nil)
	if !strings.Contains(summary, manifest.PlaceholderTrunkInterface) {
		t.Fatalf("expected formatPlanSummary to note %q when UsedPlaceholderTrunk=true, got:\n%s",
			manifest.PlaceholderTrunkInterface, summary)
	}
}

func TestAcquireReconcileLockSharedFallbacks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission fallback tests require non-root uid")
	}

	ctx := context.Background()

	t.Run("read-only existing lockfile falls back to O_RDONLY and takes LOCK_SH", func(t *testing.T) {
		dir := t.TempDir()
		lockPath := filepath.Join(dir, "state.json.lock")
		if err := os.WriteFile(lockPath, nil, 0o444); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

		release, err := acquireReconcileLockShared(ctx, lockPath)
		if err != nil {
			t.Fatalf("acquireReconcileLockShared failed on read-only lockfile: %v", err)
		}
		defer release()

		// Another LOCK_SH succeeds while LOCK_EX|LOCK_NB fails with EWOULDBLOCK.
		probe, err := os.OpenFile(lockPath, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Close()

		if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
			t.Fatalf("expected concurrent LOCK_SH to succeed, got: %v", err)
		}
		_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)

		if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
			t.Fatal("expected LOCK_EX|LOCK_NB to fail while LOCK_SH is held")
		}
	})

	t.Run("missing lockfile in unwritable parent dir returns no-op release", func(t *testing.T) {
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })

		lockPath := filepath.Join(parent, "sub", "state.json.lock")
		release, err := acquireReconcileLockShared(ctx, lockPath)
		if err != nil {
			t.Fatalf("expected no-op success when lockfile missing and parent dir unwritable, got: %v", err)
		}
		release()
	})
}

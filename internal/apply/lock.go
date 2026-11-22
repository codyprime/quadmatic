package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const lockPollInterval = 25 * time.Millisecond

// acquireReconcileLock acquires an exclusive non-blocking advisory flock on lockPath,
// polling every 25ms until the lock is acquired or ctx is canceled.
func acquireReconcileLock(ctx context.Context, lockPath string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir := filepath.Dir(lockPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create lock directory %q: %w", dir, err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file %q: %w", lockPath, err)
	}

	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = f.Close()
			return nil, fmt.Errorf("flock %q: %w", lockPath, err)
		}

		timer := time.NewTimer(lockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

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
	return flockFile(ctx, f, lockPath, syscall.LOCK_EX|syscall.LOCK_NB)
}

// acquireReconcileLockShared acquires a shared non-blocking advisory flock on lockPath,
// polling every 25ms until the lock is acquired or ctx is canceled. For non-root dry-runs,
// it falls back to O_RDONLY when the existing lockfile is read-only or not writable, and
// returns a no-op release if the lockfile does not exist and its parent directory is not writable.
func acquireReconcileLockShared(ctx context.Context, lockPath string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := openSharedLockFile(lockPath)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return func() {}, nil
	}
	return flockFile(ctx, f, lockPath, syscall.LOCK_SH|syscall.LOCK_NB)
}

func openSharedLockFile(lockPath string) (*os.File, error) {
	dir := filepath.Dir(lockPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		if isAccessOrReadOnlyErr(err) {
			f, roErr := os.OpenFile(lockPath, os.O_RDONLY, 0)
			if roErr == nil {
				return f, nil
			}
			if errors.Is(roErr, os.ErrNotExist) {
				return nil, nil
			}
			return nil, fmt.Errorf("open lock file %q: %w", lockPath, roErr)
		}
		return nil, fmt.Errorf("create lock directory %q: %w", dir, err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil {
		return f, nil
	}
	if !isAccessOrReadOnlyErr(err) {
		return nil, fmt.Errorf("open lock file %q: %w", lockPath, err)
	}

	f, roErr := os.OpenFile(lockPath, os.O_RDONLY, 0)
	if roErr == nil {
		return f, nil
	}
	if errors.Is(roErr, os.ErrNotExist) {
		return nil, nil
	}
	return nil, fmt.Errorf("open lock file %q: %w", lockPath, roErr)
}

func isAccessOrReadOnlyErr(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EROFS)
}

func flockFile(ctx context.Context, f *os.File, lockPath string, how int) (func(), error) {
	for {
		err := syscall.Flock(int(f.Fd()), how)
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

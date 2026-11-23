package fsutil

import (
	"context"
	"os"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
)

// LockFile takes an exclusive process lock until the returned file is closed.
// Keep the file in place: unlinking it would let concurrent callers lock
// different inodes. The OS releases the lock when the descriptor or process dies.
func LockFile(path string, wait bool) (*os.File, error) {
	return openLock(path, os.O_CREATE|os.O_RDWR, wait)
}

// LockExisting takes a lock without creating a marker or requiring write access.
func LockExisting(path string, wait bool) (*os.File, error) {
	return openLock(path, os.O_RDONLY, wait)
}

func openLock(path string, flags int, wait bool) (*os.File, error) {
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f, wait); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// LockFileContext waits for an exclusive lock without blocking cancellation.
func LockFileContext(ctx context.Context, c clock.Clock, root *os.Root, path string) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := root.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if ctx.Done() == nil {
		if err := lockFile(f, true); err != nil {
			_ = f.Close()
			return nil, err
		}
		return f, nil
	}
	for ctx.Err() == nil {
		err = lockFile(f, false)
		if err == nil {
			if err = ctx.Err(); err == nil {
				return f, nil
			}
			break
		}
		if !lockBusy(err) {
			_ = f.Close()
			return nil, err
		}
		if err = clock.Wait(ctx, c, 25*time.Millisecond); err != nil {
			break
		}
	}
	_ = f.Close()
	return nil, ctx.Err()
}

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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f, wait); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// LockFileContext waits for an exclusive lock without trapping a cancelled
// operation inside an OS lock call.
func LockFileContext(ctx context.Context, c clock.Clock, path string) (*os.File, error) {
	if ctx.Done() == nil {
		return LockFile(path, true)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
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

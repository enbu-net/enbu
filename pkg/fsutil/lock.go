package fsutil

import "os"

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

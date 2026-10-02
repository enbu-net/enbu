package identity

import "os"

// Keep the file in place: unlinking it would let concurrent callers lock
// different inodes. The OS releases the lock when the descriptor or process dies.
func acquireCreationLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockCreationFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

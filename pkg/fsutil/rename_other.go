//go:build !windows

package fsutil

import (
	"errors"
	"os"
	"syscall"
)

// transientRenameError is always false: a rename replaces an open file on
// these platforms, so a failure does not pass on its own.
func transientRenameError(error) bool { return false }

// syncDir makes the entries of dir, such as a name a rename just created,
// durable. A file system that cannot sync a directory (some FUSE and network
// file systems) is not an error: the rename itself has succeeded.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil && !errors.Is(err, errors.ErrUnsupported) && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

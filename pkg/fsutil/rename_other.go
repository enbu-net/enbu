//go:build !windows

package fsutil

import "os"

// transientRenameError is always false: a rename replaces an open file on
// these platforms, so a failure does not pass on its own.
func transientRenameError(error) bool { return false }

// syncDir makes the entries of dir, such as a name a rename just created,
// durable.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

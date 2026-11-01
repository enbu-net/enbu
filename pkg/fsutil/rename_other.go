//go:build !windows

package fsutil

// transientRenameError is always false: a rename replaces an open file on
// these platforms, so a failure does not pass on its own.
func transientRenameError(error) bool { return false }

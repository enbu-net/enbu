package fsutil

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockFile(f *os.File, wait bool) error {
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if !wait {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	return windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &windows.Overlapped{})
}

func lockBusy(err error) bool { return errors.Is(err, windows.ERROR_LOCK_VIOLATION) }

func openDirectoryLock(dir, sidecar string) (*os.File, error) {
	// os.OpenFile does not share the handle for deletion on Windows.
	return os.OpenFile(filepath.Join(dir, sidecar), os.O_CREATE|os.O_RDWR, 0o600)
}

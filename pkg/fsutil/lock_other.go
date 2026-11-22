//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package fsutil

import (
	"errors"
	"os"
)

func lockFile(*os.File, bool) error {
	return errors.New("file locks are not supported on this platform")
}

func lockBusy(error) bool { return false }

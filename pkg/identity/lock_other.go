//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package identity

import (
	"errors"
	"os"
)

func lockCreationFile(*os.File) error {
	return errors.New("identity creation locks are not supported on this platform")
}

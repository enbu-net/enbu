//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package identity

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockCreationFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

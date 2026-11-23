//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(f *os.File, wait bool) error {
	flags := unix.LOCK_EX
	if !wait {
		flags |= unix.LOCK_NB
	}
	for {
		err := unix.Flock(int(f.Fd()), flags)
		if err != unix.EINTR {
			return err
		}
	}
}

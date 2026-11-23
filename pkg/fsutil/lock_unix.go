//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package fsutil

import (
	"errors"
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

func lockBusy(err error) bool { return errors.Is(err, unix.EWOULDBLOCK) }

// flock can lock the directory inode itself, which git clean never removes.
func openDirectoryLock(dir, _ string) (*os.File, error) { return os.Open(dir) }

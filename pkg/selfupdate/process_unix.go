//go:build !windows

package selfupdate

import (
	"errors"
	"os"
	"syscall"
)

func processAlive(pid int) bool {
	// EPERM: the process exists but belongs to someone else.
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// ownedPrivately reports whether this user owns the directory and nobody
// else may write to it.
func ownedPrivately(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid() && info.Mode().Perm()&0o022 == 0
}

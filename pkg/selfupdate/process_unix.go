//go:build !windows

package selfupdate

import (
	"errors"
	"syscall"
)

func processAlive(pid int) bool {
	// EPERM: the process exists but belongs to someone else.
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

//go:build linux || darwin

package config

import (
	"os"
	"syscall"
)

// Replacing the inode must not change which Unix group can read a shared
// configuration. If ownership cannot be preserved, leave the old file intact.
func preserveProjectOwner(file *os.File, previous os.FileInfo) error {
	if previous == nil || !previous.Mode().IsRegular() {
		return nil
	}
	current, err := file.Stat()
	if err != nil {
		return err
	}
	oldStat := previous.Sys().(*syscall.Stat_t)
	newStat := current.Sys().(*syscall.Stat_t)
	uid, gid := -1, -1
	if oldStat.Uid != newStat.Uid {
		uid = int(oldStat.Uid)
	}
	if oldStat.Gid != newStat.Gid {
		gid = int(oldStat.Gid)
	}
	if uid == -1 && gid == -1 {
		return nil
	}
	return file.Chown(uid, gid)
}

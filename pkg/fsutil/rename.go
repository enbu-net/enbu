// Package fsutil holds file system helpers that behave the same on every
// platform.
package fsutil

import (
	"os"
	"path/filepath"
	"time"
)

// renameAttempts and renameBackoff bound how long Rename keeps retrying: seven
// sleeps doubling from 5 ms, about 0.6 s in all, which outlasts a typical
// antivirus scan of a small file.
const (
	renameAttempts = 8
	renameBackoff  = 5 * time.Millisecond
)

// Rename renames oldpath to newpath, replacing newpath if it exists. On
// Windows a replace fails while another process, such as an antivirus scanner,
// the search indexer or another enbu, has newpath open without sharing delete
// access. Those failures pass on their own, so Rename retries them for a short
// while instead of failing the whole operation.
//
// On Unix the rename is then made durable: the directories that hold the old
// and new names are synced, without which ext4, XFS and btrfs may lose the
// rename, and with it a new identity or checkpoint, on a power failure.
func Rename(oldpath, newpath string) error {
	if err := retry(func() error { return os.Rename(oldpath, newpath) }, transientRenameError, time.Sleep); err != nil {
		return err
	}
	return syncRenamed(oldpath, newpath)
}

// syncRenamed syncs the directory of newpath, and that of oldpath when it is
// another one.
func syncRenamed(oldpath, newpath string) error {
	newDir := filepath.Dir(newpath)
	if err := syncDir(newDir); err != nil {
		return err
	}
	if oldDir := filepath.Dir(oldpath); oldDir != newDir {
		return syncDir(oldDir)
	}
	return nil
}

func retry(op func() error, transient func(error) bool, sleep func(time.Duration)) error {
	delay := renameBackoff
	var err error
	for attempt := 1; ; attempt++ {
		if err = op(); err == nil || !transient(err) || attempt == renameAttempts {
			return err
		}
		sleep(delay)
		delay *= 2
	}
}

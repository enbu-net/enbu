// Package fsutil holds file system helpers that behave the same on every
// platform.
package fsutil

import (
	"os"
	"time"
)

// renameAttempts and renameBackoff bound how long Rename keeps retrying: about
// one second in all, which outlasts a typical antivirus scan of a small file.
const (
	renameAttempts = 8
	renameBackoff  = 5 * time.Millisecond
)

// Rename renames oldpath to newpath, replacing newpath if it exists. On
// Windows a replace fails while another process, such as an antivirus scanner,
// the search indexer or another enbu, has newpath open without sharing delete
// access. Those failures pass on their own, so Rename retries them for a short
// while instead of failing the whole operation.
func Rename(oldpath, newpath string) error {
	return retry(func() error { return os.Rename(oldpath, newpath) }, transientRenameError, time.Sleep)
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

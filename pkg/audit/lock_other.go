//go:build !unix && !windows

package audit

import (
	"errors"
	"os"
)

func lockJournalFile(*os.File) error {
	return errors.New("audit: inter-process journal locking is unsupported on this platform")
}

func unlockJournalFile(*os.File) error { return nil }

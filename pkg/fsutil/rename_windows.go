package fsutil

import (
	"errors"

	"golang.org/x/sys/windows"
)

// transientRenameError reports the errors another process holding the target
// open causes. They clear once that process closes the file.
func transientRenameError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

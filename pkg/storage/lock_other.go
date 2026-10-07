//go:build !unix && !windows && fixture

package storage

import (
	"errors"
	"os"
)

func tryLock(_ *os.File) (bool, error) {
	return false, errors.New("local storage locking is unsupported on this platform")
}
func unlock(_ *os.File) {}

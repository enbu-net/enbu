//go:build linux || darwin

package cas

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func protectManagedRootPath(root *os.Root, name, _ string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	return root.Chmod(name, mode)
}

func syncOpenedDirectory(directory *os.File) error {
	if err := directory.Sync(); err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil
		}
		return err
	}
	return nil
}

func rejectOpenedPlatformSpecial(*os.File, string) error { return nil }

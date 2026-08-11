//go:build linux || darwin

package host

import (
	"os"

	"golang.org/x/sys/unix"
)

func openNativeNoFollow(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func rejectOpenedNativeSpecial(*os.File) error { return nil }
func rejectNativeSpecial(string) error         { return nil }
func validateNativePath(string) error          { return nil }

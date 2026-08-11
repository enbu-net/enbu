//go:build !linux && !darwin && !windows

package host

import "os"

func openNativeNoFollow(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}

func rejectOpenedNativeSpecial(*os.File) error { return nil }
func rejectNativeSpecial(string) error         { return nil }
func validateNativePath(string) error          { return nil }

//go:build !linux && !darwin && !windows

package cas

import "os"

func protectManagedRootPath(root *os.Root, name, _ string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	return root.Chmod(name, mode)
}

func syncOpenedDirectory(*os.File) error                 { return nil }
func rejectOpenedPlatformSpecial(*os.File, string) error { return nil }

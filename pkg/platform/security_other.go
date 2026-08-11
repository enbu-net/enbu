//go:build !linux && !darwin && !windows

package platform

import (
	"fmt"
	"os"
)

func protectOpenedFile(file *os.File, _ string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	return file.Chmod(mode)
}

func validatePrivateOpenedFile(file *os.File, directory bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	if info.Mode().Perm() != want {
		return fmt.Errorf("%w: mode %o, want %o", ErrInsecureFile, info.Mode().Perm(), want)
	}
	return nil
}

func replaceFile(root *os.Root, temporary, destination string) error {
	return root.Rename(temporary, destination)
}

func syncDirectory(*os.Root) error                       { return nil }
func rejectPlatformSpecial(string) error                 { return nil }
func validatePlatformPath(string) error                  { return nil }
func canonicalizeParentPath(path string) (string, error) { return path, nil }

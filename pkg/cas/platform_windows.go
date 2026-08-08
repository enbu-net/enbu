//go:build windows

package cas

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func syncDirectory(string) error { return nil }

func openNoFollow(path string) (*os.File, error) {
	if err := rejectPlatformSpecial(path); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func rejectPlatformSpecial(path string) error {
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pathUTF16)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: path %q is a reparse point", ErrUnsafePath, path)
	}
	return nil
}

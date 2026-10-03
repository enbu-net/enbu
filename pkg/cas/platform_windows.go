//go:build windows

package cas

import (
	"fmt"

	"golang.org/x/sys/windows"
)

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

//go:build windows

package host

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func openNativeNoFollow(root *os.Root, name string) (*os.File, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	parent, err := finalPathByHandle(directory)
	if err != nil {
		return nil, err
	}
	path, err := windows.UTF16PtrFromString(filepath.Join(parent, name))
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("create pinned file from native handle")
	}
	return file, nil
}

func finalPathByHandle(file *os.File) (string, error) {
	buffer := make([]uint16, 100)
	for {
		length, err := windows.GetFinalPathNameByHandle(
			windows.Handle(file.Fd()),
			&buffer[0],
			uint32(len(buffer)),
			0,
		)
		if err != nil {
			return "", err
		}
		if length < uint32(len(buffer)) {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		buffer = make([]uint16, length+1)
	}
}

func rejectOpenedNativeSpecial(file *os.File) error {
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &information); err != nil {
		return err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("opened path is a reparse point")
	}
	return nil
}

func rejectNativeSpecial(path string) error {
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pathUTF16)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("path contains a reparse point")
	}
	return nil
}

func validateNativePath(path string) error {
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return errors.New("UNC and device paths are unsupported")
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return errors.New("path must use an absolute drive")
	}
	remainder := strings.TrimPrefix(path, volume)
	for _, segment := range strings.FieldsFunc(remainder, func(r rune) bool { return r == '\\' || r == '/' }) {
		if strings.Contains(segment, ":") || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return errors.New("path contains an unsafe Windows segment")
		}
		base := strings.ToUpper(segment)
		if index := strings.IndexByte(base, '.'); index >= 0 {
			base = base[:index]
		}
		if isReservedWindowsName(base) {
			return errors.New("path contains a reserved Windows name")
		}
	}
	return nil
}

func isReservedWindowsName(name string) bool {
	switch name {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$":
		return true
	}
	if len(name) == 4 && name[3] >= '1' && name[3] <= '9' {
		return strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")
	}
	return false
}

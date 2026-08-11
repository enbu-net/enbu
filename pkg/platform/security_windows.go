//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	systemSID     = "S-1-5-18"
	volumeNameDOS = 0
)

func protectOpenedFile(_ *os.File, path string, directory bool) error {
	acl, err := privateACL(directory)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

func privateACL(directory bool) (*windows.ACL, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	system, err := windows.StringToSid(systemSID)
	if err != nil {
		return nil, err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := []windows.EXPLICIT_ACCESS{
		privateAccessEntry(user.User.Sid, inheritance),
		privateAccessEntry(system, inheritance),
	}
	return windows.ACLFromEntries(entries, nil)
}

func privateAccessEntry(sid *windows.SID, inheritance uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func validatePrivateOpenedFile(file *os.File, directory bool) error {
	sd, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: DACL inherits from its parent", ErrInsecureFile)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || dacl.AceCount != 2 {
		return fmt.Errorf("%w: DACL must contain exactly two entries", ErrInsecureFile)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.StringToSid(systemSID)
	if err != nil {
		return err
	}
	foundUser := false
	foundSystem := false
	wantInheritance := uint8(0)
	if directory {
		wantInheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&windows.GENERIC_ALL == 0 {
			return fmt.Errorf("%w: DACL contains a non-private entry", ErrInsecureFile)
		}
		if ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != wantInheritance {
			return fmt.Errorf("%w: DACL has incorrect inheritance", ErrInsecureFile)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		foundUser = foundUser || sid.Equals(user.User.Sid)
		foundSystem = foundSystem || sid.Equals(system)
	}
	if !foundUser || !foundSystem {
		return fmt.Errorf("%w: DACL must grant only the current user and SYSTEM", ErrInsecureFile)
	}
	return nil
}

func replaceFile(root *os.Root, temporary, destination string) error {
	parent, err := finalRootPath(root)
	if err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(filepath.Join(parent, temporary))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(parent, destination))
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(
		from,
		to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
	if err == nil {
		return nil
	}
	if isBusyReplaceError(err) {
		return errors.Join(ErrDestinationBusy, err)
	}
	return err
}

func finalRootPath(root *os.Root) (string, error) {
	directory, err := root.Open(".")
	if err != nil {
		return "", err
	}
	defer directory.Close()
	buffer := make([]uint16, 100)
	for {
		length, err := windows.GetFinalPathNameByHandle(
			windows.Handle(directory.Fd()),
			&buffer[0],
			uint32(len(buffer)),
			volumeNameDOS,
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

func isBusyReplaceError(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_USER_MAPPED_FILE)
}

// Windows does not expose a portable directory fsync operation. File.Sync and
// the atomic same-directory rename provide the strongest supported boundary.
func syncDirectory(*os.Root) error { return nil }

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

func validatePlatformPath(path string) error {
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return fmt.Errorf("%w: UNC and device paths are not supported", ErrUnsafePath)
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return fmt.Errorf("%w: path must use an absolute drive path", ErrUnsafePath)
	}
	remainder := strings.TrimPrefix(path, volume)
	for _, segment := range strings.FieldsFunc(remainder, func(r rune) bool { return r == '\\' || r == '/' }) {
		if strings.Contains(segment, ":") || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return fmt.Errorf("%w: unsafe Windows path segment %q", ErrUnsafePath, segment)
		}
		base := strings.ToUpper(segment)
		if index := strings.IndexByte(base, '.'); index >= 0 {
			base = base[:index]
		}
		if isReservedWindowsName(base) {
			return fmt.Errorf("%w: reserved Windows path segment %q", ErrUnsafePath, segment)
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

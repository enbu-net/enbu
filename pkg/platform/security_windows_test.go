//go:build windows

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsBusyReplaceErrorClassification(t *testing.T) {
	busy := []error{
		windows.ERROR_SHARING_VIOLATION,
		windows.ERROR_LOCK_VIOLATION,
		windows.ERROR_ACCESS_DENIED,
		windows.ERROR_USER_MAPPED_FILE,
		&os.LinkError{Op: "rename", Old: "old", New: "new", Err: windows.ERROR_SHARING_VIOLATION},
	}
	for _, err := range busy {
		if !isBusyReplaceError(err) {
			t.Errorf("isBusyReplaceError(%v) = false", err)
		}
	}
	if isBusyReplaceError(windows.ERROR_INVALID_PARAMETER) {
		t.Fatal("ERROR_INVALID_PARAMETER classified as busy")
	}
}

func TestWindowsPrivateACLAndValidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	writer, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	acl, err := privateACL(false)
	if err != nil {
		t.Fatal(err)
	}
	if acl.AceCount != 2 {
		t.Fatalf("private ACL entries = %d, want 2", acl.AceCount)
	}
}

func TestWindowsBusyDestinationIsUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "credential")
	initial, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initial.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := initial.Commit(); err != nil {
		t.Fatal(err)
	}

	replacement, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Write([]byte("replacement")); err != nil {
		t.Fatal(err)
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	commitErr := replacement.Commit()
	if closeErr := windows.CloseHandle(handle); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(commitErr, ErrDestinationBusy) {
		t.Fatalf("Commit error = %v, want ErrDestinationBusy", commitErr)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Fatalf("busy destination content = %q, want original", content)
	}
	assertNoSecureWriterTemps(t, dir)
}

func TestWindowsExistingParentDACLIsUnchanged(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(
		parent,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}

	writer, err := NewSecureWriter(filepath.Join(parent, "materialized-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(
		parent,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("existing parent DACL changed from %q to %q", before.String(), after.String())
	}
}

func TestWindowsMissingParentGetsPrivateDACL(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "enbu-private", "materialized")
	writer, err := NewSecureWriter(filepath.Join(parent, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Abort() })
	directory, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := validatePrivateOpenedFile(directory, true); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsPathValidationRejectsNativeAliases(t *testing.T) {
	unsafePaths := []string{
		`\\server\share\credential`,
		`\\?\C:\private\credential`,
		`C:\private\NUL`,
		`C:\private\credential.`,
		`C:\private\credential `,
		`C:\private\credential:stream`,
	}
	for _, path := range unsafePaths {
		if err := validateUsableAbsolute(path); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("validateUsableAbsolute(%q) error = %v", path, err)
		}
	}
}

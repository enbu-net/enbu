package platform

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecureWriterCommitsPrivateFileAndReplacesExistingContent(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data")
	path := filepath.Join(dir, "credential")

	writer, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Abort() })
	if filepath.Dir(filepath.Join(dir, writer.tempName)) != dir {
		t.Fatalf("temporary file %q is not in destination directory %q", writer.tempName, dir)
	}
	if runtime.GOOS != "windows" {
		info, err := writer.file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("temporary file mode = %o, want 600", got)
		}
	}
	if _, err := io.WriteString(writer, "first"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	assertPrivateContent(t, path, "first")
	assertNoSecureWriterTemps(t, dir)

	replacement, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replacement.Abort() })
	if _, err := io.WriteString(replacement, "second"); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Commit(); err != nil {
		t.Fatal(err)
	}
	assertPrivateContent(t, path, "second")
	assertNoSecureWriterTemps(t, dir)
}

func TestSecureWriterAbortLeavesDestinationUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	writer, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatalf("second Abort = %v", err)
	}
	assertPrivateContent(t, path, "original")
	assertNoSecureWriterTemps(t, dir)
	if _, err := writer.Write([]byte("x")); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("Write after Abort error = %v", err)
	}
	if err := writer.Commit(); !errors.Is(err, ErrWriterClosed) {
		t.Fatalf("Commit after Abort error = %v", err)
	}
}

func TestSecureWriterAbortDoesNotCreateMissingDestination(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "credential")
	writer, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "discarded"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination after Abort error = %v", err)
	}
	assertNoSecureWriterTemps(t, dir)
}

func TestSecureWriterDataSyncFailureLeavesDestinationUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "credential")
	writer, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "discarded"); err != nil {
		t.Fatal(err)
	}
	if err := writer.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err == nil {
		t.Fatal("Commit succeeded after the temporary file was closed")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination after failed Commit error = %v", err)
	}
	assertNoSecureWriterTemps(t, dir)
}

func TestSecureWriterReplaceFailureLeavesDestinationUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	writer, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "replacement"); err != nil {
		t.Fatal(err)
	}
	replaceErr := errors.New("injected replace failure")
	writer.replace = func(*os.Root, string, string) error { return replaceErr }
	if err := writer.Commit(); !errors.Is(err, replaceErr) {
		t.Fatalf("Commit error = %v", err)
	}
	assertPrivateContent(t, path, "original")
	assertNoSecureWriterTemps(t, dir)
}

func TestSecureWriterParentSyncFailureOccursAfterReplacement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "credential")
	writer, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "replacement"); err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("injected parent sync failure")
	writer.syncDirectory = func(*os.Root) error { return syncErr }
	if err := writer.Commit(); !errors.Is(err, syncErr) {
		t.Fatalf("Commit error = %v", err)
	}
	assertPrivateContent(t, path, "replacement")
	if err := writer.Abort(); err != nil {
		t.Fatalf("Abort after replacement = %v", err)
	}
}

func TestSecureWriterRejectsUnsafeDestinations(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name string
		path string
	}{
		{name: "relative", path: "relative"},
		{name: "unclean", path: filepath.Join(root, "data") + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "credential"},
		{name: "nul", path: filepath.Join(root, "credential") + "\x00suffix"},
		{name: "filesystem root", path: filepath.VolumeName(root) + string(os.PathSeparator)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSecureWriter(test.path); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("NewSecureWriter(%q) error = %v", test.path, err)
			}
		})
	}

	directoryTarget := filepath.Join(root, "directory-target")
	if err := EnsurePrivateDir(directoryTarget); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSecureWriter(directoryTarget); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("directory destination error = %v", err)
	}
}

func TestSecureWriterRejectsSymlinkComponentsAndDestination(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := EnsurePrivateDir(realDir); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkedDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewSecureWriter(filepath.Join(linkedDir, "credential")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink parent error = %v", err)
	}

	target := filepath.Join(realDir, "target")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(realDir, "credential")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := NewSecureWriter(link); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink destination error = %v", err)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Fatalf("symlink target content = %q", content)
	}
}

func TestEnsurePrivateDirAndValidatePrivateFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("directory mode = %o, want 700", got)
		}
	}
	path := filepath.Join(dir, "credential")
	writer, err := NewSecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile("relative"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("relative file error = %v", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := ValidatePrivateFile(path); !errors.Is(err, ErrInsecureFile) {
			t.Fatalf("insecure mode error = %v", err)
		}
	}
}

func TestSecureWriterDoesNotChangeExistingParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows DACL preservation is covered by the native test")
	}
	parent := filepath.Join(t.TempDir(), "repository")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}

	writer, err := NewSecureWriter(filepath.Join(parent, "materialized-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("existing parent mode = %o, want unchanged 755", got)
	}
}

func TestSecureWriterCreatesEveryMissingParentPrivately(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "repository")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(existing, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	first := filepath.Join(existing, "enbu-private")
	parent := filepath.Join(first, "materialized")
	writer, err := NewSecureWriter(filepath.Join(parent, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Abort() })
	if runtime.GOOS == "windows" {
		return
	}
	existingInfo, err := os.Stat(existing)
	if err != nil {
		t.Fatal(err)
	}
	if got := existingInfo.Mode().Perm(); got != 0o755 {
		t.Fatalf("existing ancestor mode = %o, want unchanged 755", got)
	}
	for _, directory := range []string{first, parent} {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("created parent %q mode = %o, want 700", directory, got)
		}
	}
}

func TestProcessLockIsScopedAndReleasable(t *testing.T) {
	var lock Lock
	release := lock.Acquire()
	release()
	release = lock.Acquire()
	release()
}

func assertPrivateContent(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != want {
		t.Fatalf("content = %q, want %q", content, want)
	}
	if err := ValidatePrivateFile(path); err != nil {
		t.Fatal(err)
	}
}

func assertNoSecureWriterTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary file remains after writer completed: %q", entry.Name())
		}
	}
}

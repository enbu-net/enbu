package platform

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureWriterAndPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := EnsurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	file, err := SecureWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("credential")); err != nil {
		t.Fatal(err)
	}
	if err := SyncAndClose(file); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := SecureWriter(path); err == nil {
		t.Fatal("SecureWriter accepted existing file")
	}
}

func TestRejectsSymlinkAndRelativePaths(t *testing.T) {
	if err := EnsurePrivateDir("relative"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("relative directory error = %v", err)
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := ValidatePrivateFile(link); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink validation error = %v", err)
	}
}

func TestProcessLockIsScopedAndReleasable(t *testing.T) {
	var lock Lock
	release := lock.Acquire()
	release()
	release = lock.Acquire()
	release()
}

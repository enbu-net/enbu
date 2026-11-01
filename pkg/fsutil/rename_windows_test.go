package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestTransientRenameErrors(t *testing.T) {
	for _, err := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION} {
		if !transientRenameError(&os.LinkError{Op: "rename", Err: err}) {
			t.Errorf("%v is not treated as transient", err)
		}
	}
	if transientRenameError(&os.LinkError{Op: "rename", Err: windows.ERROR_FILE_NOT_FOUND}) {
		t.Error("ERROR_FILE_NOT_FOUND is treated as transient")
	}
}

// TestRenameWaitsForOpenTarget holds the target open without delete sharing,
// as a scanner does, and releases it while Rename is retrying.
func TestRenameWaitsForOpenTarget(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "from"), filepath.Join(dir, "to")
	if err := os.WriteFile(from, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(to)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = windows.CloseHandle(h)
		close(released)
	}()
	if err := Rename(from, to); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	<-released
	if b, err := os.ReadFile(to); err != nil || string(b) != "new" {
		t.Fatalf("target = %q, %v; want new", b, err)
	}
	if _, err := os.Stat(from); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists: %v", err)
	}
}

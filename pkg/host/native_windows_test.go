//go:build windows

package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeCapabilitiesRejectUnsafeWindowsSyntax(t *testing.T) {
	paths := []string{`\\server\share\secret`, `C:\safe\secret:stream`, `C:\safe\CON`}
	for _, path := range paths {
		if _, err := NewFileInput(path); !errors.Is(err, ErrUnsafeFileInput) {
			t.Fatalf("NewFileInput(%q) error = %v", path, err)
		}
		if _, err := NewSecureFileOutput(path); !errors.Is(err, ErrUnsafeFileOutput) {
			t.Fatalf("NewSecureFileOutput(%q) error = %v", path, err)
		}
	}
}

func TestFileInputRejectsWindowsReparsePoint(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating a Windows symlink requires developer mode or privilege: %v", err)
	}
	input, err := NewFileInput(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := input.Open(context.Background()); !errors.Is(err, ErrUnsafeFileInput) {
		t.Fatalf("reparse input error = %v", err)
	}
}

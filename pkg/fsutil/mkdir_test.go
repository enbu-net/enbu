package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMkdirAllCreatesDurableNestedDirectories(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "first", "second")
	for range 2 {
		if err := MkdirAll(target, 0700); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(target); err != nil || !info.IsDir() {
			t.Fatalf("directory absent: %v %v", info, err)
		}
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAll(filepath.Join(file, "child"), 0700); err == nil {
		t.Fatal("file used as parent directory")
	}
}

//go:build unix && fixture

package storage

import (
	"os"
	"testing"
)

func TestSyncDirectory(t *testing.T) {
	r, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := syncDirectory(r); err != nil {
		t.Fatalf("syncing an open directory: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := syncDirectory(r); err == nil {
		t.Fatal("syncing a closed root succeeded")
	}
}

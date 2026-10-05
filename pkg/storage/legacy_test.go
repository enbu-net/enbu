package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalHasLegacy(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	detect := func() bool {
		t.Helper()
		got, err := NewLocal(dir).Refs.(LegacyDetector).HasLegacy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if detect() {
		t.Fatal("empty directory reported as legacy")
	}
	if _, err := os.Stat(filepath.Join(dir, "refs")); err == nil {
		t.Fatal("detection must not create the new layout")
	}
	if err := os.WriteFile(filepath.Join(dir, "enbu-workspace.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !detect() {
		t.Fatal("legacy .json object not detected")
	}
}

func TestLocalHasLegacyMissingDirectory(t *testing.T) {
	got, err := NewLocal(filepath.Join(t.TempDir(), "absent")).Refs.(LegacyDetector).HasLegacy(context.Background())
	if err != nil || got {
		t.Fatalf("got %v, %v", got, err)
	}
}

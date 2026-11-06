package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOutputPublicationFailurePreservesExistingEntry(t *testing.T) {
	for _, failure := range []string{"canceled", "rename"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "output")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if failure == "canceled" {
				if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
					t.Fatal(err)
				}
				cancel()
			} else {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "original"), []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := writePrivateOutput(ctx, path, []byte("private-replacement"))
			if err == nil || failure == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("publication error = %v", err)
			}
			want, originalPath := "original", path
			if failure == "rename" {
				want, originalPath = "keep", filepath.Join(path, "original")
			}
			got, err := os.ReadFile(originalPath)
			if err != nil || string(got) != want {
				t.Fatalf("original entry changed: err=%v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "output" {
				t.Fatalf("failed publication left plaintext temporary files: entries=%v err=%v", entries, err)
			}
		})
	}
}

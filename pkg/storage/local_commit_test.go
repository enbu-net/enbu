package storage

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestCommitLocalFile(t *testing.T) {
	syncFailure := errors.New("directory sync failed")
	for _, tc := range []struct {
		name        string
		missingFile bool
		syncErr     error
	}{
		{name: "success"},
		{name: "rename failure", missingFile: true},
		{name: "sync failure after replacement", syncErr: syncFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			if err := r.WriteFile("object.json", []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !tc.missingFile {
				if err := r.WriteFile(".pending-test", []byte("new"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			syncCalls := 0
			err = commitLocalFile(r, ".pending-test", "object.json", func(root *os.Root) error {
				syncCalls++
				got, err := root.ReadFile("object.json")
				if err != nil || string(got) != "new" {
					t.Fatalf("directory synced before replacement: %q, %v", got, err)
				}
				return tc.syncErr
			})
			want := "new"
			if tc.missingFile {
				want = "old"
				if !errors.Is(err, fs.ErrNotExist) || syncCalls != 0 {
					t.Fatalf("rename failure: err=%v, sync calls=%d", err, syncCalls)
				}
			} else {
				if syncCalls != 1 || !errors.Is(err, tc.syncErr) {
					t.Fatalf("sync result: err=%v, sync calls=%d", err, syncCalls)
				}
				if tc.syncErr != nil && !strings.Contains(err.Error(), "update is already visible") {
					t.Fatalf("sync error does not explain the committed replacement: %v", err)
				}
			}
			got, readErr := r.ReadFile("object.json")
			if readErr != nil || string(got) != want {
				t.Fatalf("object=%q, want %q: %v", got, want, readErr)
			}
		})
	}
}

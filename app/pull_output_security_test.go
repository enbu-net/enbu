package app

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPullReplacesOutputWithoutFollowingLinks(t *testing.T) {
	for _, kind := range []string{"regular", "hardlink", "symlink"} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/replace-%t", kind, replace), func(t *testing.T) {
				a := newAlice(t)
				path := filepath.Join(a.RepositoryDir, ".env")
				target := filepath.Join(t.TempDir(), "unrelated-file")
				original := []byte("LOCAL_ONLY=personal\n")
				if err := os.WriteFile(target, original, 0o644); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "regular":
					if err := os.WriteFile(path, original, 0o644); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					if err := os.Link(target, path); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(target, path); err != nil {
						if runtime.GOOS == "windows" {
							t.Skipf("symlink privilege unavailable: %v", err)
						}
						t.Fatal(err)
					}
				}
				if _, err := a.PullSecretsToFileWith(t.Context(), "default", replace); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() {
					t.Fatalf("output is not a regular file: info=%v err=%v", info, err)
				}
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
					t.Errorf("secret output permissions = %o, want 600", info.Mode().Perm())
				}
				data, err := os.ReadFile(path)
				if err != nil || !strings.Contains(string(data), "KEY=") || strings.Contains(string(data), "LOCAL_ONLY=") == replace {
					t.Errorf("output did not preserve the requested local-variable policy: err=%v", err)
				}
				got, err := os.ReadFile(target)
				if err != nil || string(got) != string(original) {
					t.Errorf("pull modified an unrelated linked file: err=%v", err)
				}
			})
		}
	}
}

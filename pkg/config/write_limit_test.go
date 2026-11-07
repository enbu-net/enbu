//go:build linux || darwin

package config

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The kernel performs a real partial write and returns EFBIG. Keep the limit
// and SIGXFSZ policy in a subprocess so other tests and coverage are unaffected.
func TestSaveProjectSurvivesPartialWrite(t *testing.T) {
	if dir := os.Getenv("ENBU_CONFIG_WRITE_LIMIT_CHILD"); dir != "" {
		projectWriteLimitChild(t, dir, os.Getenv("ENBU_CONFIG_WRITE_LIMIT_EXISTING") == "1")
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, existing := range []bool{false, true} {
		name := "new"
		if existing {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if existing {
				if err := SaveProjectTo(dir, atomicProjectFixture("before")); err != nil {
					t.Fatal(err)
				}
			}
			child := exec.CommandContext(t.Context(), executable, "-test.run=^TestSaveProjectSurvivesPartialWrite$")
			child.Dir = dir
			flag := "0"
			if existing {
				flag = "1"
			}
			child.Env = append(os.Environ(), "ENBU_CONFIG_WRITE_LIMIT_CHILD="+dir, "ENBU_CONFIG_WRITE_LIMIT_EXISTING="+flag)
			if out, err := child.CombinedOutput(); err != nil {
				t.Fatalf("partial-write subprocess: %v\n%s", err, out)
			}
			want, err := MarshalProject(atomicProjectFixture("after"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "enbu.toml"))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("recovery did not save the exact configuration: %v", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "enbu.toml" {
				t.Fatalf("failed write retained temporary files: %v %v", entries, err)
			}
		})
	}
}

func projectWriteLimitChild(t *testing.T, dir string, existing bool) {
	t.Helper()
	cfg := atomicProjectFixture("after")
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &original); err != nil {
		t.Fatal(err)
	}
	limited := original
	limited.Cur = 32
	signal.Ignore(syscall.SIGXFSZ)
	err := func() error {
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &limited); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &original); err != nil {
				t.Fatal(err)
			}
		}()
		return SaveProjectTo(dir, cfg)
	}()
	signal.Reset(syscall.SIGXFSZ)
	if !errors.Is(err, unix.EFBIG) {
		t.Fatalf("kernel partial-write cause was not preserved: %v", err)
	}
	path := filepath.Join(dir, "enbu.toml")
	got, readErr := os.ReadFile(path)
	if existing {
		want, err := MarshalProject(atomicProjectFixture("before"))
		if err != nil {
			t.Fatal(err)
		}
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("failed write changed the existing configuration: got %d bytes, %v", len(got), readErr)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		t.Fatalf("failed first save left a partial configuration: got %d bytes, %v", len(got), readErr)
	}
	if err := SaveProjectTo(dir, cfg); err != nil {
		t.Fatalf("retry after lifting the file limit: %v", err)
	}
	loaded, err := LoadProjectFrom(dir)
	if err != nil || loaded.DefaultEnv != "after" {
		t.Fatalf("recovered configuration is unreadable: %v", err)
	}
}

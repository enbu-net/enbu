package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func atomicProjectFixture(name string) *ProjectConfig {
	cfg := NewProjectWithIDs(name, func() string { return "00000000-0000-4000-8000-000000000001" })
	cfg.Storage.URL = "oci://registry.example/team/secrets"
	return cfg
}

func TestSaveProjectToDoesNotReplaceAncestorConfiguration(t *testing.T) {
	parent := t.TempDir()
	original, err := MarshalProject(atomicProjectFixture("parent"))
	if err != nil {
		t.Fatal(err)
	}
	parentPath := filepath.Join(parent, "enbu.toml")
	if err := os.WriteFile(parentPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveProjectTo(child, atomicProjectFixture("child")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(parentPath)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("explicit destination overwrote its ancestor: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(child, "enbu.toml"))
	want, marshalErr := MarshalProject(atomicProjectFixture("child"))
	if err != nil || marshalErr != nil || !bytes.Equal(got, want) {
		t.Fatalf("explicit destination did not receive the complete configuration: %v %v", err, marshalErr)
	}
}

func TestSaveProjectDiscoversImplicitAncestorDestination(t *testing.T) {
	parent := t.TempDir()
	original, err := MarshalProject(atomicProjectFixture("before"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "enbu.toml")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	if err := SaveProject(atomicProjectFixture("after")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	want, marshalErr := MarshalProject(atomicProjectFixture("after"))
	if err != nil || marshalErr != nil || !bytes.Equal(got, want) {
		t.Fatalf("implicit destination did not update its discovered ancestor: %v %v", err, marshalErr)
	}
	if _, err := os.Stat(filepath.Join(child, "enbu.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("implicit destination created a shadow configuration: %v", err)
	}
}

func TestSaveProjectPreservesRegularFilePermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "enbu.toml")
			if err := SaveProjectTo(dir, atomicProjectFixture("before")); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if err := SaveProjectTo(dir, atomicProjectFixture("after")); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != mode {
				t.Fatalf("file permissions changed: %v want %v", info.Mode().Perm(), mode)
			}
		})
	}
}

func TestNewProjectConfigurationIsPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := SaveProjectTo(dir, atomicProjectFixture("default")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "enbu.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("new configuration exposed group/other access: %v", info.Mode())
	}
}

func TestSaveProjectReplacesLinksWithoutChangingTheirTargets(t *testing.T) {
	for _, link := range []string{"hard", "symbolic"} {
		t.Run(link, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "unrelated.toml")
			original, err := MarshalProject(atomicProjectFixture("before"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, original, 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "enbu.toml")
			if link == "hard" {
				err = os.Link(target, path)
			} else {
				err = os.Symlink(target, path)
			}
			if err != nil {
				// Windows may require SeCreateSymbolicLinkPrivilege. Other
				// fixture failures must remain test failures on every platform.
				if runtime.GOOS == "windows" && link == "symbolic" && (errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.Errno(1314))) {
					t.Skipf("symbolic links are unavailable: %v", err)
				}
				t.Fatal(err)
			}
			if err := SaveProjectTo(dir, atomicProjectFixture("after")); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("configuration save overwrote the linked target: %v", err)
			}
			want, err := MarshalProject(atomicProjectFixture("after"))
			if err != nil {
				t.Fatal(err)
			}
			got, err = os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("replacement did not contain the exact new configuration: %v", err)
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() {
				t.Fatalf("replacement is not a regular file: %v", err)
			}
		})
	}
}

func TestSaveProjectCleansTemporaryFileAfterRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enbu.toml")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	neighbor := filepath.Join(path, "keep")
	if err := os.WriteFile(neighbor, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveProjectTo(dir, atomicProjectFixture("after")); err == nil {
		t.Fatal("replacing a non-empty directory was acknowledged")
	}
	got, err := os.ReadFile(neighbor)
	if err != nil || string(got) != "untouched" {
		t.Fatalf("rename failure changed an existing entry: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "enbu.toml" {
		t.Fatalf("rename failure retained temporary files: %v %v", entries, err)
	}
}

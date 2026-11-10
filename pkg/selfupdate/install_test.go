package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []interface{ Close() error }{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInstallLinuxReplacesTheBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "enbu-desktop")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "update.tar.gz")
	writeTarGz(t, archive, map[string]string{"./enbu-desktop": "new", "./README": "x"})

	if err := Install(context.Background(), "linux", archive, target); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	if got := readFile(t, target); got != "new" {
		t.Errorf("target = %q, want new", got)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Errorf("target is not executable: %v %v", info, err)
	}
	if _, err := os.Stat(target + ".new"); !os.IsNotExist(err) {
		t.Errorf("target.new left behind: %v", err)
	}
}

func TestInstallKeepsTheAppWhenTheArchiveLacksTheBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "enbu-desktop")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "update.tar.gz")
	writeTarGz(t, archive, map[string]string{"./other": "x"})

	if err := Install(context.Background(), "linux", archive, target); err == nil {
		t.Fatal("Install() = nil, want an error")
	}
	if got := readFile(t, target); got != "old" {
		t.Errorf("target = %q, want old", got)
	}
	if _, err := os.Stat(target + ".new"); !os.IsNotExist(err) {
		t.Errorf("target.new left behind: %v", err)
	}
}

func TestInstallWindowsMovesTheRunningBinaryAside(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "enbu-desktop.exe")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "update.zip")
	writeZip(t, archive, map[string]string{"enbu-desktop.exe": "new"})

	if err := Install(context.Background(), "windows", archive, target); err != nil {
		t.Fatalf("Install() = %v", err)
	}
	if got := readFile(t, target); got != "new" {
		t.Errorf("target = %q, want new", got)
	}
	if got := readFile(t, target+".old"); got != "old" {
		t.Errorf("target.old = %q, want old", got)
	}
	CleanUp(target)
	if _, err := os.Stat(target + ".old"); !os.IsNotExist(err) {
		t.Errorf("CleanUp left target.old: %v", err)
	}
}

func TestSwapDirs(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "enbu-desktop.app")
	next := target + ".new"
	for path, body := range map[string]string{target: "old", next: "new"} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "Info.plist"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := swapDirs(target, next); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(target, "Info.plist")); got != "new" {
		t.Errorf("bundle = %q, want new", got)
	}
	for _, leftover := range []string{next, target + ".old"} {
		if _, err := os.Stat(leftover); !os.IsNotExist(err) {
			t.Errorf("%s left behind", leftover)
		}
	}
}

func TestInstallRefusesOtherSystems(t *testing.T) {
	if err := Install(context.Background(), "plan9", "a", "b"); err == nil {
		t.Error("Install(plan9) = nil")
	}
}

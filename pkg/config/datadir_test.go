package config

import (
	"path/filepath"
	"testing"
)

// abs makes a slash path absolute on the host, so the cases hold on Windows,
// where "/data" has no drive letter.
func abs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(filepath.FromSlash(p))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDataDirIsAlwaysAbsolute(t *testing.T) {
	homePath := abs(t, "/home/kota")
	home := func() string { return homePath }
	env := func(vars map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := vars[k]; ok && v != "data" {
				return abs(t, v)
			}
			return vars[k]
		}
	}
	tests := []struct {
		name string
		goos string
		vars map[string]string
		home func() string
		want string
	}{
		{"xdg", "linux", map[string]string{"XDG_DATA_HOME": "/data"}, home, "/data/enbu"},
		// The XDG Base Directory specification says relative paths are invalid.
		{"relative xdg", "linux", map[string]string{"XDG_DATA_HOME": "data"}, home, "/home/kota/.local/share/enbu"},
		{"linux", "linux", nil, home, "/home/kota/.local/share/enbu"},
		{"darwin", "darwin", nil, home, "/home/kota/Library/Application Support/enbu"},
		{"windows", "windows", map[string]string{"LOCALAPPDATA": "/local"}, home, "/local/enbu"},
		{"windows without LOCALAPPDATA", "windows", nil, home, "/home/kota/AppData/Local/enbu"},
		{"no home", "linux", nil, func() string { return abs(t, unresolvedHome) }, "/nonexistent/.local/share/enbu"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dataDir(tt.goos, env(tt.vars), tt.home)
			if want := abs(t, tt.want); got != want {
				t.Fatalf("dataDir = %q, want %q", got, want)
			}
		})
	}
}

func TestUnresolvedHomeIsAbsolute(t *testing.T) {
	if !filepath.IsAbs(unresolvedHome) {
		t.Fatalf("unresolvedHome = %q, want an absolute path", unresolvedHome)
	}
}

func TestHomeDirWithoutHOME(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if got := homeDir(); !filepath.IsAbs(got) {
		t.Fatalf("homeDir() = %q, want an absolute path", got)
	}
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("LOCALAPPDATA", "")
	if got := DataDir(); !filepath.IsAbs(got) {
		t.Fatalf("DataDir() = %q, want an absolute path", got)
	}
}

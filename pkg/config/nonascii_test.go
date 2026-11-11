package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Home folders and repositories often have Japanese names and spaces
// (C:\Users\山田 太郎, ~/Documents/開発 プロジェクト).
const nonASCIIDir = "日本語 フォルダ (テスト)"

func TestDataDirInNonASCIIHome(t *testing.T) {
	home := abs(t, "/Users/山田 太郎")
	local := abs(t, "/Users/山田 太郎/AppData/Local")
	for goos, want := range map[string]string{
		"linux":   filepath.Join(home, ".local", "share", "enbu"),
		"darwin":  filepath.Join(home, "Library", "Application Support", "enbu"),
		"windows": filepath.Join(local, "enbu"),
	} {
		getenv := func(name string) string {
			if name == "LOCALAPPDATA" {
				return local
			}
			return ""
		}
		if got := dataDir(goos, getenv, func() string { return home }); got != want {
			t.Errorf("%s: dataDir = %q, want %q", goos, got, want)
		}
	}
}

func TestProjectAndGUIConfigInNonASCIIPaths(t *testing.T) {
	base := filepath.Join(t.TempDir(), nonASCIIDir)
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "データ"))
	repo := filepath.Join(base, "リポジトリ")
	sub := filepath.Join(repo, "サブ フォルダ")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := NewProjectWithEnvironment("default")
	if err := SaveProjectTo(repo, cfg); err != nil {
		t.Fatal(err)
	}
	// A command run in a subfolder finds the enbu.toml above it.
	path, err := ProjectConfigPathFrom(sub)
	if err != nil || path != filepath.Join(repo, "enbu.toml") {
		t.Fatalf("ProjectConfigPathFrom = %q, %v", path, err)
	}
	loaded, err := LoadProjectFrom(sub)
	if err != nil || loaded.WorkspaceID != cfg.WorkspaceID {
		t.Fatalf("LoadProjectFrom = %+v, %v", loaded, err)
	}
	gui := &GUIConfig{SelectedRepo: repo, RepoHistory: []string{repo, sub}}
	if err := SaveGUI(gui); err != nil {
		t.Fatal(err)
	}
	got, err := LoadGUI()
	if err != nil || got.SelectedRepo != repo || !slices.Equal(got.RepoHistory, gui.RepoHistory) {
		t.Fatalf("LoadGUI = %+v, %v", got, err)
	}
}

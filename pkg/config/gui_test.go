package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadGUIMissing(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	cfg, err := LoadGUI()
	if err != nil {
		t.Fatalf("LoadGUI: %v", err)
	}
	if cfg.SelectedRepo != "" {
		t.Fatalf("SelectedRepo = %q, want empty", cfg.SelectedRepo)
	}
}

func TestSaveAndLoadGUI(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	want := filepath.Join(t.TempDir(), "repo")

	if err := SaveGUI(&GUIConfig{SelectedRepo: want}); err != nil {
		t.Fatalf("SaveGUI: %v", err)
	}

	cfg, err := LoadGUI()
	if err != nil {
		t.Fatalf("LoadGUI: %v", err)
	}
	if cfg.SelectedRepo != want {
		t.Fatalf("SelectedRepo = %q, want %q", cfg.SelectedRepo, want)
	}
}

func TestGUIConfigRepoHistory(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	want := []string{"/path/a", "/path/b"}

	if err := SaveGUI(&GUIConfig{SelectedRepo: "/path/a", RepoHistory: want}); err != nil {
		t.Fatalf("SaveGUI: %v", err)
	}

	cfg, err := LoadGUI()
	if err != nil {
		t.Fatalf("LoadGUI: %v", err)
	}
	if len(cfg.RepoHistory) != 2 || cfg.RepoHistory[0] != "/path/a" || cfg.RepoHistory[1] != "/path/b" {
		t.Fatalf("RepoHistory = %v, want %v", cfg.RepoHistory, want)
	}
}

func TestLoadGUILegacyNoHistory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)

	if err := os.MkdirAll(filepath.Join(dir, "enbu"), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte("selected_repo = \"/some/path\"\n")
	if err := os.WriteFile(filepath.Join(dir, "enbu", "gui.toml"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadGUI()
	if err != nil {
		t.Fatalf("LoadGUI: %v", err)
	}
	if cfg.SelectedRepo != "/some/path" {
		t.Fatalf("SelectedRepo = %q", cfg.SelectedRepo)
	}
	if cfg.RepoHistory != nil {
		t.Fatalf("RepoHistory = %v, want nil", cfg.RepoHistory)
	}
}

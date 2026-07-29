package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
)

func TestSwitchCreate(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	content := `version = "v1alpha1"
default_env = "default"

[env.default]
output = ".env"
`
	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644)

	a := &app.App{}
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"switch", "-c", "staging"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("switch -c staging: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "enbu.toml"))
	if !strings.Contains(string(data), "staging") {
		t.Fatal("staging not in enbu.toml")
	}
	if !strings.Contains(string(data), `default_env = "staging"`) {
		t.Fatal("default not set to staging")
	}
}

func TestSwitchToExisting(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	content := `version = "v1alpha1"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"
`
	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644)

	a := &app.App{}
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"switch", "staging"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("switch staging: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "enbu.toml"))
	if !strings.Contains(string(data), `default_env = "staging"`) {
		t.Fatal("default not set to staging")
	}
}

func TestSwitchNonExistent(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	content := `version = "v1alpha1"
default_env = "dev"

[env.dev]
output = ".env.dev"
`
	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644)

	a := &app.App{}
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"switch", "prod"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for non-existent env")
	}
}

type staticRepoDetector struct{ owner, repo string }

func (s *staticRepoDetector) LoadRepo() (string, string, error) { return s.owner, s.repo, nil }

func TestSwitchPrevious(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	content := `version = "v1alpha1"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"
`
	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644)

	a := &app.App{RepoDetector: &staticRepoDetector{owner: "test", repo: "repo"}}

	cmd1 := NewWithApp("test", a)
	cmd1.SetArgs([]string{"switch", "staging"})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("switch staging: %v", err)
	}

	cmd2 := NewWithApp("test", a)
	cmd2.SetArgs([]string{"switch", "-"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("switch -: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "enbu.toml"))
	if !strings.Contains(string(data), `default_env = "dev"`) {
		t.Fatalf("expected default to be dev, got: %s", data)
	}
}

func TestSwitchDelete(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	content := `version = "v1alpha1"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"
`
	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644)

	a := &app.App{}
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"switch", "-d", "staging"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("switch -d staging: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "enbu.toml"))
	if strings.Contains(string(data), "staging") {
		t.Fatal("staging still in enbu.toml")
	}
}

func TestSwitchDeleteCurrentFails(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	content := `version = "v1alpha1"
default_env = "dev"

[env.dev]
output = ".env.dev"
`
	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644)

	a := &app.App{}
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"switch", "-d", "dev"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when deleting current env")
	}
}

func TestSwitchList(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	content := `version = "v1alpha1"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"
`
	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644)

	a := &app.App{}
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"switch", "--list"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("switch --list: %v", err)
	}
}

func TestSwitchMove(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	content := `version = "v1alpha1"
default_env = "dev"

[env.dev]
output = ".env.dev"
`
	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644)

	a := &app.App{}
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"switch", "-m", "dev", "development"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("switch -m dev development: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "enbu.toml"))
	if strings.Contains(string(data), "[env.dev]") {
		t.Fatal("dev still in enbu.toml")
	}
	if !strings.Contains(string(data), "development") {
		t.Fatal("development not in enbu.toml")
	}
	if !strings.Contains(string(data), `default_env = "development"`) {
		t.Fatal("default not updated to development")
	}
}

func TestSwitchRejectsTwoArgs(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	_ = os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(`version = "v1alpha1"
default_env = "dev"
[env.dev]
output = ".env.dev"
`), 0o644)

	a := &app.App{}
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"switch", "dev", "extra"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when two positional args given")
	}
}

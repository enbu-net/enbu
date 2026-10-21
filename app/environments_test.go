package app

import (
	"os"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

// SwitchEnvironment should not panic when no local state exists
func TestSwitchEnvironmentWithoutLocalFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	cfg := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"
`
	if err := os.WriteFile("enbu.toml", []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{
		RepositoryDir: dir,
		RepoDetector:  &staticRepoDetector{owner: "test", repo: "repo"},
	}
	if err := a.SwitchEnvironment("staging"); err != nil {
		t.Fatalf("SwitchEnvironment: %v", err)
	}
}

func TestSwitchEnvironmentRejectsInvalidName(t *testing.T) {
	a := &App{RepositoryDir: t.TempDir()}
	err := a.SwitchEnvironment("bad/name")
	if !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("SwitchEnvironment error = %v, want %q", err, apperr.CodeInvalidArgument)
	}
}

func TestDeleteEnvironmentRejectsCurrent(t *testing.T) {
	dir := t.TempDir()
	cfg := `version = "v1alpha2"
default_env = "dev"

[env.dev]
output = ".env.dev"
`
	if err := os.WriteFile(dir+"/enbu.toml", []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{RepositoryDir: dir}
	err := a.DeleteEnvironment("dev")
	if !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("DeleteEnvironment error = %v, want %q", err, apperr.CodeInvalidArgument)
	}
}

// An environment added to enbu.toml by hand has no incarnation and is stored
// under its name. Renaming it must keep its secrets.
func TestRenamingAHandWrittenEnvironmentKeepsItsSecrets(t *testing.T) {
	a := newAlice(t)
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Environments["staging"] = config.EnvironmentConfig{Output: ".env.staging"}
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.AddSecret(bg, "staging", "TOKEN", "kept"); err != nil {
		t.Fatal(err)
	}
	if err := a.RenameEnvironment("staging", "stage"); err != nil {
		t.Fatal(err)
	}
	got, err := a.ListSecrets(bg, "stage")
	if err != nil || got["TOKEN"] != "kept" {
		t.Fatalf("secrets after rename: %v %v", got, err)
	}
}

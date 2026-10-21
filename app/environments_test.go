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

// Which environment a person works in is theirs: switching must not change
// the shared enbu.toml, and renaming follows their choice.
func TestSwitchingIsPersonal(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	shared := `version = "v1alpha2"
workspace_id = "11111111-1111-4111-8111-111111111111"
default_env = "dev"

[env.dev]
output = ".env.dev"

[env.staging]
output = ".env.staging"
`
	if err := os.WriteFile(dir+"/enbu.toml", []byte(shared), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{RepositoryDir: dir}
	if err := a.SwitchEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(dir + "/enbu.toml"); string(data) != shared {
		t.Fatalf("switching changed enbu.toml:\n%s", data)
	}
	if current, _ := a.CurrentEnvironment(); current != "staging" {
		t.Fatalf("current = %q", current)
	}
	envs, err := a.ListEnvironments()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range envs {
		if e.IsCurrent != (e.Name == "staging") {
			t.Fatalf("environments = %+v", envs)
		}
	}
	if err := a.RenameEnvironment("staging", "stage"); err != nil {
		t.Fatal(err)
	}
	if current, _ := a.CurrentEnvironment(); current != "stage" {
		t.Fatalf("current after rename = %q", current)
	}
	if err := a.DeleteEnvironment("stage"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("deleting the current environment: %v", err)
	}
	// Another person sharing enbu.toml still works in the team default.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	if current, _ := a.CurrentEnvironment(); current != "dev" {
		t.Fatalf("another person's current = %q, want the team default", current)
	}
}

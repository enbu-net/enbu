package app

import (
	"os"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

// SwitchEnvironment should not panic when no local state exists
func TestSwitchEnvironmentWithoutLocalFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	cfg := `version = "v1alpha1"
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
	cfg := `version = "v1alpha1"
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

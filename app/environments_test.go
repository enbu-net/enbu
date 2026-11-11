package app

import (
	"bytes"
	"os"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

func TestEnvironmentChangesRejectOutputCollisionWithoutWritingConfig(t *testing.T) {
	for _, operation := range []string{"create", "rename"} {
		t.Run(operation, func(t *testing.T) {
			dir := t.TempDir()
			before := []byte("version = 'v1alpha2'\ndefault_env = 'prod'\n[env.prod]\noutput = '.ENV.blocked'\n[env.staging]\n")
			if err := os.WriteFile(dir+"/enbu.toml", before, 0o644); err != nil {
				t.Fatal(err)
			}
			a := &App{RepositoryDir: dir}
			var err error
			if operation == "create" {
				err = a.CreateEnvironment("blocked")
			} else {
				err = a.RenameEnvironment("staging", "blocked")
			}
			if !apperr.Is(err, apperr.CodeInvalidArgument) {
				t.Fatalf("environment operation accepted an output collision: %v", err)
			}
			after, err := os.ReadFile(dir + "/enbu.toml")
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected operation changed configuration: %v", err)
			}
		})
	}
}

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
	// With no workspace yet there is no local state, so the switch sets the
	// team default in enbu.toml.
	written, err := config.LoadProjectFrom(dir)
	if err != nil {
		t.Fatal(err)
	}
	if written.DefaultEnv != "staging" {
		t.Fatalf("default_env = %q, want staging", written.DefaultEnv)
	}
	if err := a.RenameEnvironment("staging", "stage"); err != nil {
		t.Fatalf("RenameEnvironment: %v", err)
	}
	if current, _ := a.CurrentEnvironment(); current != "stage" {
		t.Fatalf("current after rename = %q, want stage", current)
	}
	if entries, _ := os.ReadDir(os.Getenv("XDG_DATA_HOME")); len(entries) != 0 {
		t.Fatalf("a workspace without workspace_id wrote local state: %v", entries)
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
	_, err := a.DeleteEnvironment(bg, "dev", false)
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
	if _, err := a.DeleteEnvironment(bg, "stage", false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("deleting the current environment: %v", err)
	}
	// Another person sharing enbu.toml still works in the team default.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	if current, _ := a.CurrentEnvironment(); current != "dev" {
		t.Fatalf("another person's current = %q, want the team default", current)
	}
}

// A local state that cannot be read must stop commands, not send them to the
// team default without a word.
func TestUnreadableLocalStateIsReported(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	shared := "version = \"v1alpha2\"\nworkspace_id = \"11111111-1111-4111-8111-111111111111\"\ndefault_env = \"dev\"\n\n[env.dev]\noutput = \".env.dev\"\n\n[env.staging]\noutput = \".env.staging\"\n"
	if err := os.WriteFile(dir+"/enbu.toml", []byte(shared), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{RepositoryDir: dir}
	if err := a.SwitchEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	path := config.LocalStatePath("11111111-1111-4111-8111-111111111111")
	if err := os.WriteFile(path, []byte("current = [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if current, err := a.CurrentEnvironment(); err == nil {
		t.Fatalf("CurrentEnvironment = %q with a broken local state", current)
	}
	if err := a.RenameEnvironment("staging", "stage"); err == nil {
		t.Fatal("RenameEnvironment ignored a broken local state")
	}
}

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseGitRemoteSSH(t *testing.T) {
	owner, repo, err := ParseGitRemote("git@github.com:enbu-net/enbu.git")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "enbu-net" || repo != "enbu" {
		t.Fatalf("got %s/%s, want enbu-net/enbu", owner, repo)
	}
}

func TestParseGitRemoteHTTPS(t *testing.T) {
	owner, repo, err := ParseGitRemote("https://github.com/enbu-net/enbu.git")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "enbu-net" || repo != "enbu" {
		t.Fatalf("got %s/%s, want enbu-net/enbu", owner, repo)
	}
}

func TestParseGitRemoteHTTPSNoSuffix(t *testing.T) {
	owner, repo, err := ParseGitRemote("https://github.com/enbu-net/enbu")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "enbu-net" || repo != "enbu" {
		t.Fatalf("got %s/%s, want enbu-net/enbu", owner, repo)
	}
}

func TestParseGitRemoteSSHNoSuffix(t *testing.T) {
	owner, repo, err := ParseGitRemote("git@github.com:org/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "org" || repo != "repo" {
		t.Fatalf("got %s/%s, want org/repo", owner, repo)
	}
}

func TestParseGitRemoteTrailingSlash(t *testing.T) {
	owner, repo, err := ParseGitRemote("https://github.com/enbu-net/enbu/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "enbu-net" || repo != "enbu" {
		t.Fatalf("got %s/%s, want enbu-net/enbu", owner, repo)
	}
}

func TestParseGitRemoteInvalid(t *testing.T) {
	_, _, err := ParseGitRemote("not-a-url")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestParseGitRemoteInvalidSSH(t *testing.T) {
	_, _, err := ParseGitRemote("git@github.com")
	if err == nil {
		t.Fatal("expected error for invalid SSH URL without colon")
	}
}

func TestLoadProjectConfig(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	content := `version = "v1alpha1"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProject()
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	if cfg.Version != "v1alpha1" {
		t.Fatalf("got version %q, want %q", cfg.Version, "v1alpha1")
	}
	env, err := cfg.Environment("default")
	if err != nil {
		t.Fatalf("Environment(default): %v", err)
	}
	if env.Output != ".env" {
		t.Fatalf("got output %q, want .env", env.Output)
	}
}

func TestLoadProjectConfigWithEnvironments(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	content := `version = "v1alpha1"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.production"
`
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProject()
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	dev, err := cfg.Environment("dev")
	if err != nil {
		t.Fatalf("Environment(dev): %v", err)
	}
	if dev.Output != ".env.dev" {
		t.Fatalf("got dev output %q, want .env.dev", dev.Output)
	}
	prod, err := cfg.Environment("prod")
	if err != nil {
		t.Fatalf("Environment(prod): %v", err)
	}
	if prod.Output != ".env.production" {
		t.Fatalf("got prod output %q, want .env.production", prod.Output)
	}
	if _, err := cfg.Environment("stage"); err == nil {
		t.Fatal("expected undefined environment to fail")
	}
}

func TestLoadProjectConfigNotFound(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	_, err = LoadProject()
	if err == nil {
		t.Fatal("expected error when enbu.toml not found")
	}
}

func TestLoadProjectUnsupportedVersion(t *testing.T) {
	versions := []string{"", "0.1", "v2", "1.0"}
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			dir := t.TempDir()
			origDir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(origDir) })
			if err := os.Chdir(dir); err != nil {
				t.Fatal(err)
			}
			content := fmt.Sprintf("version = %q\n", v)
			if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err = LoadProject()
			if err == nil {
				t.Fatalf("expected error for version %q", v)
			}
		})
	}
}

func TestEnvironmentWithoutSection(t *testing.T) {
	cfg := &ProjectConfig{Version: "v1alpha1"}
	env, err := cfg.Environment("default")
	if err != nil {
		t.Fatalf("Environment(default) with no sections: %v", err)
	}
	if env.Output != ".env" {
		t.Fatalf("got output %q, want .env", env.Output)
	}

	if _, err = cfg.Environment("dev"); err == nil {
		t.Fatal("expected error for undefined non-default env without sections")
	}
}

func TestSaveProject(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg := NewProjectWithEnvironment("dev")
	if err := SaveProject(cfg); err != nil {
		t.Fatalf("SaveProject: %v", err)
	}

	loaded, err := LoadProject()
	if err != nil {
		t.Fatalf("LoadProject after save: %v", err)
	}
	if loaded.Version != "v1alpha1" {
		t.Fatalf("got version %q, want %q", loaded.Version, "v1alpha1")
	}
	if loaded.DefaultEnv != "dev" {
		t.Fatalf("got default %q, want dev", loaded.DefaultEnv)
	}
	env, err := loaded.Environment("dev")
	if err != nil {
		t.Fatalf("Environment(dev): %v", err)
	}
	if env.Output != ".env.dev" {
		t.Fatalf("got output %q, want .env.dev", env.Output)
	}
}

func TestMarshalProjectUsesFlatEnvironmentTables(t *testing.T) {
	cfg := NewProjectWithEnvironment("default")
	content, err := MarshalProject(cfg)
	if err != nil {
		t.Fatalf("MarshalProject: %v", err)
	}
	want := "version = \"v1alpha1\"\ndefault_env = \"default\"\n\n[env.default]\noutput = \".env\"\n"
	if string(content) != want {
		t.Fatalf("unexpected TOML:\n%s\nwant:\n%s", content, want)
	}
}

func TestMarshalProjectSortsAndQuotesEnvironmentNames(t *testing.T) {
	cfg := &ProjectConfig{
		Version:    "v1alpha1",
		DefaultEnv: "a.b",
		Environments: map[string]EnvironmentConfig{
			"z":   {Output: ".env.z"},
			"a.b": {Output: ".env.dotted"},
		},
	}
	content, err := MarshalProject(cfg)
	if err != nil {
		t.Fatalf("MarshalProject: %v", err)
	}
	want := "version = \"v1alpha1\"\ndefault_env = \"a.b\"\n\n[env.\"a.b\"]\noutput = \".env.dotted\"\n\n[env.z]\noutput = \".env.z\"\n"
	if string(content) != want {
		t.Fatalf("unexpected TOML:\n%s\nwant:\n%s", content, want)
	}
}

func TestEnvironmentNamesAreStableAndSorted(t *testing.T) {
	cfg := &ProjectConfig{
		Environments: map[string]EnvironmentConfig{
			"staging":     {Output: ".env.staging"},
			"development": {Output: ".env.development"},
			"production":  {Output: ".env.production"},
		},
	}
	want := []string{"development", "production", "staging"}
	for range 10 {
		if got := cfg.EnvironmentNames(); !slices.Equal(got, want) {
			t.Fatalf("EnvironmentNames() = %v, want %v", got, want)
		}
	}
}

func TestNewProjectWithEnvironment(t *testing.T) {
	cfg := NewProjectWithEnvironment("dev")
	if cfg.DefaultEnv != "dev" {
		t.Fatalf("got default %q, want dev", cfg.DefaultEnv)
	}
	dev, err := cfg.Environment("dev")
	if err != nil {
		t.Fatalf("Environment(dev): %v", err)
	}
	if dev.Output != ".env.dev" {
		t.Fatalf("got dev output %q, want .env.dev", dev.Output)
	}
}

func TestNewProjectWithEnvironmentDefault(t *testing.T) {
	cfg := NewProjectWithEnvironment("")
	if cfg.DefaultEnv != "default" {
		t.Fatalf("got default %q, want default", cfg.DefaultEnv)
	}
	env, err := cfg.Environment("default")
	if err != nil {
		t.Fatalf("Environment(default): %v", err)
	}
	if env.Output != ".env" {
		t.Fatalf("got output %q, want .env", env.Output)
	}
}

func TestAddEnvironment(t *testing.T) {
	cfg := NewProjectWithEnvironment("dev")
	if err := cfg.AddEnvironment("staging"); err != nil {
		t.Fatalf("AddEnvironment: %v", err)
	}
	if !cfg.HasEnvironment("staging") {
		t.Fatal("staging should exist")
	}
	if err := cfg.AddEnvironment("staging"); err == nil {
		t.Fatal("expected error for duplicate environment")
	}
}

func TestRemoveEnvironment(t *testing.T) {
	cfg := NewProjectWithEnvironment("dev")
	_ = cfg.AddEnvironment("staging")
	if err := cfg.RemoveEnvironment("staging"); err != nil {
		t.Fatalf("RemoveEnvironment: %v", err)
	}
	if cfg.HasEnvironment("staging") {
		t.Fatal("staging should not exist")
	}
}

func TestRenameEnvironment(t *testing.T) {
	cfg := NewProjectWithEnvironment("dev")
	if err := cfg.RenameEnvironment("dev", "development"); err != nil {
		t.Fatalf("RenameEnvironment: %v", err)
	}
	if cfg.HasEnvironment("dev") {
		t.Fatal("dev should not exist")
	}
	if !cfg.HasEnvironment("development") {
		t.Fatal("development should exist")
	}
	if cfg.DefaultEnv != "development" {
		t.Fatalf("default should be updated, got %q", cfg.DefaultEnv)
	}
}

func TestValidEnvironmentName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"default", true},
		{"dev", true},
		{"stage-1", true},
		{"prod.us", true},
		{"", false},
		{"prod/us", false},
		{"prod us", false},
	}
	for _, tt := range tests {
		if got := ValidEnvironmentName(tt.name); got != tt.want {
			t.Errorf("ValidEnvironmentName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

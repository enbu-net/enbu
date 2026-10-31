package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"uuid"
)

func TestNewProjectWorkspaceIDs(t *testing.T) {
	first := NewProjectWithEnvironment("default")
	second := NewProjectWithEnvironment("default")
	if first.WorkspaceID == second.WorkspaceID {
		t.Fatal("different workspaces share an identity")
	}
	for _, cfg := range []*ProjectConfig{first, second} {
		id, err := uuid.Parse(cfg.WorkspaceID)
		if err != nil {
			t.Fatalf("invalid workspace UUID %q: %v", cfg.WorkspaceID, err)
		}
		if id.String() != cfg.WorkspaceID || id[6]>>4 != 4 || id[8]>>6 != 2 {
			t.Fatalf("workspace ID is not a canonical RFC 9562 UUID v4: %q", cfg.WorkspaceID)
		}
	}
}

func TestParseGitHubRemote(t *testing.T) {
	for _, remote := range []string{
		"git@github.com:enbu-net/enbu.git",
		"git@github.com:enbu-net/enbu",
		"https://github.com/enbu-net/enbu.git",
		"https://github.com/enbu-net/enbu",
		"https://github.com/enbu-net/enbu/",
		"https://user@github.com/enbu-net/enbu.git",
		"ssh://git@github.com/enbu-net/enbu.git",
	} {
		owner, repo, err := ParseGitHubRemote(remote)
		if err != nil || owner != "enbu-net" || repo != "enbu" {
			t.Errorf("%s: got %s/%s %v, want enbu-net/enbu", remote, owner, repo, err)
		}
	}
}

func TestParseGitHubRemoteRejectsOthers(t *testing.T) {
	for _, remote := range []string{
		"not-a-url",
		"git@github.com",
		"git@github.com:enbu-net",
		"https://github.com/enbu-net",
		"https://github.com/enbu-net/enbu/tree/main",
		"https://gitlab.com/enbu-net/enbu.git",
		"git@gitlab.com:enbu-net/enbu.git",
		"https://github.example.com/enbu-net/enbu.git",
		"file:///srv/git/enbu.git",
		"/srv/git/enbu.git",
	} {
		if owner, repo, err := ParseGitHubRemote(remote); err == nil {
			t.Errorf("%s: got %s/%s, want an error", remote, owner, repo)
		}
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

	content := `version = "v1alpha2"` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProject()
	if err != nil {
		t.Fatalf("LoadProject: %v", err)
	}
	if cfg.Version != "v1alpha2" {
		t.Fatalf("got version %q, want %q", cfg.Version, "v1alpha2")
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

	content := `version = "v1alpha2"

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
	cfg := &ProjectConfig{Version: "v1alpha2"}
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
	if loaded.Version != "v1alpha2" {
		t.Fatalf("got version %q, want %q", loaded.Version, "v1alpha2")
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
	want := "version = \"v1alpha2\"\ndefault_env = \"default\"\nworkspace_id = \"" + cfg.WorkspaceID + "\"\n\n[env.default]\noutput = \".env\"\nincarnation = \"" + cfg.Environments["default"].Incarnation + "\"\n"
	if string(content) != want {
		t.Fatalf("unexpected TOML:\n%s\nwant:\n%s", content, want)
	}
}

func TestMarshalProjectSortsAndQuotesEnvironmentNames(t *testing.T) {
	cfg := &ProjectConfig{
		Version:    "v1alpha2",
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
	want := "version = \"v1alpha2\"\ndefault_env = \"a.b\"\n\n[env.\"a.b\"]\noutput = \".env.dotted\"\n\n[env.z]\noutput = \".env.z\"\n"
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

func TestRenameKeepsTheStorageLineage(t *testing.T) {
	cfg := NewProjectWithEnvironment("dev")
	before := cfg.Resource("dev")
	if err := cfg.RenameEnvironment("dev", "development"); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Resource("development"); got != before {
		t.Fatalf("resource after rename = %q, want %q", got, before)
	}
}

// An environment written by hand has no incarnation and is stored under its
// name; renaming it must not make its secrets look empty.
func TestRenameOfAnEnvironmentWithoutIncarnationKeepsItsSecrets(t *testing.T) {
	cfg, err := ParseProject("version = \"v1alpha2\"\n\n[env.staging]\noutput = \".env.staging\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Resource("staging"); got != "secrets/staging" {
		t.Fatalf("resource = %q", got)
	}
	if err := cfg.RenameEnvironment("staging", "stage"); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Resource("stage"); got != "secrets/staging" {
		t.Fatalf("resource after rename = %q, want secrets/staging", got)
	}
	if env, _ := cfg.Environment("stage"); env.Output != ".env.stage" {
		t.Fatalf("default output should follow the name, got %q", env.Output)
	}
}

func TestRenameKeepsACustomOutput(t *testing.T) {
	cfg := NewProjectWithEnvironment("dev")
	env := cfg.Environments["dev"]
	env.Output = "config/app.env"
	cfg.Environments["dev"] = env
	if err := cfg.RenameEnvironment("dev", "development"); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Environments["development"].Output; got != "config/app.env" {
		t.Fatalf("output = %q", got)
	}
}

// Adding a first environment to an enbu.toml with only the implicit default
// must keep the default's secrets where they are.
func TestAddingAnEnvironmentKeepsTheImplicitDefault(t *testing.T) {
	cfg, err := ParseProject("version = \"v1alpha2\"\n")
	if err != nil {
		t.Fatal(err)
	}
	before := cfg.Resource("default")
	if err := cfg.AddEnvironment("dev"); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Resource("default"); got != before {
		t.Fatalf("default resource = %q, want %q", got, before)
	}
	if cfg.Environments["dev"].Incarnation == "" {
		t.Fatal("a new environment needs its own incarnation")
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

func TestLocalState_RoundTrip(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	want := &LocalConfig{Previous: "dev"}
	if err := SaveLocalState("myorg/myrepo", want); err != nil {
		t.Fatalf("SaveLocalState: %v", err)
	}

	got, err := LoadLocalState("myorg/myrepo")
	if err != nil {
		t.Fatalf("LoadLocalState: %v", err)
	}
	if got.Previous != want.Previous {
		t.Errorf("Previous = %q, want %q", got.Previous, want.Previous)
	}
}

func TestLoadLocalState_Missing(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	cfg, err := LoadLocalState("noorg/norepo")
	if err != nil {
		t.Fatalf("LoadLocalState: %v", err)
	}
	if cfg.Previous != "" {
		t.Errorf("Previous = %q, want empty", cfg.Previous)
	}
}

func TestLocalStatePath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/testxdg")

	path := LocalStatePath("MyOrg/MyRepo")
	want := filepath.Join("/tmp/testxdg/enbu/state", uuidOrHash("MyOrg/MyRepo")+".toml")
	if path != want {
		t.Errorf("LocalStatePath = %q, want %q", path, want)
	}
}

func TestControlGenesisSurvivesSaveAndLoad(t *testing.T) {
	cfg := NewProjectWithEnvironment("default")
	cfg.ControlGenesis = "sha256:" + strings.Repeat("a", 64)
	dir := t.TempDir()
	if err := SaveProjectTo(dir, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProjectFrom(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ControlGenesis != cfg.ControlGenesis || loaded.WorkspaceID != cfg.WorkspaceID {
		t.Fatalf("loaded %+v, want genesis %s", loaded, cfg.ControlGenesis)
	}
}

func TestProjectWithoutControlGenesisOmitsTheKey(t *testing.T) {
	b, err := MarshalProject(NewProjectWithEnvironment("default"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "control_genesis") {
		t.Fatalf("empty genesis was written:\n%s", b)
	}
}

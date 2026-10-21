package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestReadWriteConfig(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "enbu.toml")
	want := "version = \"v1alpha2\"\ndefault_env = \"default\"\n"
	if err := os.WriteFile(tomlPath, []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{RepositoryDir: dir}

	got, err := a.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if got != want {
		t.Fatalf("ReadConfig = %q, want %q", got, want)
	}

	newContent := "version = \"v1alpha2\"\ndefault_env = \"production\"\n"
	if err := a.WriteConfig(newContent); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	data, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "production") {
		t.Fatalf("written config = %q, expected to contain production", string(data))
	}
}

func TestWriteConfigRejectsOutputOutsideRepository(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "enbu.toml")
	original := "version = \"v1alpha2\"\n"
	if err := os.WriteFile(tomlPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{RepositoryDir: dir}
	err := a.WriteConfig("version = \"v1alpha2\"\n[env.dev]\noutput = \"../secrets.local\"\n")
	if err == nil {
		t.Fatal("WriteConfig succeeded for output outside repository")
	}
	data, readErr := os.ReadFile(tomlPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != original {
		t.Fatalf("config changed after rejected write: %q", data)
	}
}

func TestReadConfigMissing(t *testing.T) {
	dir := t.TempDir()
	a := &App{RepositoryDir: dir}
	_, err := a.ReadConfig()
	if !apperr.Is(err, apperr.CodeConfigNotFound) {
		t.Fatalf("ReadConfig error = %v, want %q", err, apperr.CodeConfigNotFound)
	}
}

func TestWriteConfigProtectsTrustAndStorageLineage(t *testing.T) {
	dir := t.TempDir()
	current := `version = "v1alpha2"
workspace_id = "11111111-1111-4111-8111-111111111111"
control_genesis = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
default_env = "dev"

[env.dev]
output = ".env.dev"
incarnation = "22222222-2222-4222-8222-222222222222"

[env.legacy]
output = ".env.legacy"
`
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{RepositoryDir: dir}
	cases := map[string]struct{ from, to, key string }{
		"workspace":           {`workspace_id = "11111111-1111-4111-8111-111111111111"`, `workspace_id = "33333333-3333-4333-8333-333333333333"`, "workspace_id"},
		"genesis":             {`control_genesis = "sha256:aaaa`, `control_genesis = "sha256:bbbb`, "control_genesis"},
		"genesis dropped":     {"control_genesis = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n", "", "control_genesis"},
		"incarnation":         {`incarnation = "22222222-2222-4222-8222-222222222222"`, `incarnation = "44444444-4444-4444-8444-444444444444"`, "env.dev.incarnation"},
		"incarnation dropped": {"incarnation = \"22222222-2222-4222-8222-222222222222\"\n", "", "env.dev.incarnation"},
		"lineage given":       {"output = \".env.legacy\"\n", "output = \".env.legacy\"\nincarnation = \"55555555-5555-4555-8555-555555555555\"\n", "env.legacy.incarnation"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := a.WriteConfig(strings.Replace(current, c.from, c.to, 1))
			var appErr *apperr.Error
			if !apperr.Is(err, apperr.CodeConfigProtected) || !errors.As(err, &appErr) || appErr.Params()["key"] != c.key {
				t.Fatalf("WriteConfig = %v, want config_protected for %s", err, c.key)
			}
		})
	}
	data, _ := os.ReadFile(filepath.Join(dir, "enbu.toml"))
	if string(data) != current {
		t.Fatalf("a refused edit changed enbu.toml:\n%s", data)
	}

	// Everything else stays editable, including adding and removing environments.
	edited := strings.Replace(current, `default_env = "dev"`, `default_env = "legacy"`, 1)
	edited = strings.Replace(edited, "output = \".env.dev\"", "output = \"config/dev.env\"", 1)
	edited += "\n[env.new]\noutput = \".env.new\"\n"
	if err := a.WriteConfig(edited); err != nil {
		t.Fatalf("ordinary edit: %v", err)
	}
	withoutLegacy := strings.Replace(edited, "[env.legacy]\noutput = \".env.legacy\"\n", "", 1)
	withoutLegacy = strings.Replace(withoutLegacy, `default_env = "legacy"`, `default_env = "dev"`, 1)
	if err := a.WriteConfig(withoutLegacy); err != nil {
		t.Fatalf("removing an environment: %v", err)
	}
}

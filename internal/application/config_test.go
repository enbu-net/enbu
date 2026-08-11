package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func TestReadWriteConfig(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "enbu.toml")
	want := "version = \"v1alpha1\"\ndefault_env = \"default\"\n"
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

	newContent := "version = \"v1alpha1\"\ndefault_env = \"production\"\n"
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
	original := "version = \"v1alpha1\"\n"
	if err := os.WriteFile(tomlPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{RepositoryDir: dir}
	err := a.WriteConfig("version = \"v1alpha1\"\n[env.dev]\noutput = \"../secrets.local\"\n")
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

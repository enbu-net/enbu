package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/internal/application"
)

const validProject = `version = "v1alpha1"
default_env = "default"

[env.default]
output = ".env"
`

func TestRunRejectsNilApp(t *testing.T) {
	err := Run(nil)
	if err == nil || !strings.Contains(err.Error(), "app instance is nil") {
		t.Fatalf("Run(nil) error = %v", err)
	}
}

func TestPrepareProjectAtRequiresConfigInExactDirectory(t *testing.T) {
	parent := t.TempDir()
	if err := os.WriteFile(filepath.Join(parent, "enbu.toml"), []byte(validProject), 0o644); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}

	a := &app.App{}
	err := prepareProjectAt(a, child)
	if err == nil || !strings.Contains(err.Error(), "current directory") {
		t.Fatalf("prepareProjectAt error = %v", err)
	}
	if a.RepositoryDir != "" {
		t.Fatalf("RepositoryDir = %q after failure", a.RepositoryDir)
	}
}

func TestPrepareProjectAtPinsRepositoryDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(validProject), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &app.App{}
	if err := prepareProjectAt(a, dir); err != nil {
		t.Fatal(err)
	}
	if a.RepositoryDir != dir {
		t.Fatalf("RepositoryDir = %q, want %q", a.RepositoryDir, dir)
	}
}

func TestPrepareProjectAtValidatesConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "invalid toml", content: "not = [toml"},
		{name: "unsupported version", content: "version = \"v2\"\n"},
		{name: "output escapes repository", content: "version = \"v1alpha1\"\n[env.default]\noutput = \"../outside\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := prepareProjectAt(&app.App{}, dir); err == nil {
				t.Fatal("prepareProjectAt succeeded")
			}
		})
	}
}

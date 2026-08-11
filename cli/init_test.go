//go:build legacy

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/internal/application"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
)

func TestEnsureGitignore_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()

	if err := ensureGitignore(dir); err != nil {
		t.Fatalf("ensureGitignore: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(data)
	for _, entry := range gitignoreEntries {
		if !strings.Contains(content, entry) {
			t.Errorf("missing entry %q in .gitignore", entry)
		}
	}
}

func TestEnsureGitignore_AppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	existing := "node_modules/\n*.log\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ensureGitignore(dir); err != nil {
		t.Fatalf("ensureGitignore: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.HasPrefix(content, existing) {
		t.Error("existing content was overwritten")
	}
	for _, entry := range gitignoreEntries {
		if !strings.Contains(content, entry) {
			t.Errorf("missing entry %q", entry)
		}
	}
}

func TestEnsureGitignore_NoDuplicates(t *testing.T) {
	dir := t.TempDir()
	existing := ".env\n.env.*\n!.env.example\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ensureGitignore(dir); err != nil {
		t.Fatalf("ensureGitignore: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != existing {
		t.Errorf("file was modified when all entries already exist:\ngot: %q\nwant: %q", string(data), existing)
	}
}

func TestEnsureGitignore_PartialExisting(t *testing.T) {
	dir := t.TempDir()
	existing := ".env\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ensureGitignore(dir); err != nil {
		t.Fatalf("ensureGitignore: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, ".env.*") {
		t.Error("missing .env.*")
	}
	if !strings.Contains(content, "!.env.example") {
		t.Error("missing !.env.example")
	}
	if strings.Count(content, ".env\n") != 1 {
		t.Error(".env was duplicated")
	}
}

func TestEnsureGitignore_NoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	existing := "node_modules/"
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ensureGitignore(dir); err != nil {
		t.Fatalf("ensureGitignore: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.HasPrefix(content, "node_modules/\n") {
		t.Error("newline not added after existing content without trailing newline")
	}
	for _, entry := range gitignoreEntries {
		if !strings.Contains(content, entry) {
			t.Errorf("missing entry %q", entry)
		}
	}
}

func TestEnsureGitignore_CustomOutputs(t *testing.T) {
	dir := t.TempDir()
	if err := ensureGitignore(dir, "secrets.json", "config/dev.env", `\!literal.env`); err != nil {
		t.Fatalf("ensureGitignore: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{"secrets.json", "config/dev.env", `\!literal.env`} {
		if !strings.Contains(content, want) {
			t.Errorf("missing custom output %q in .gitignore", want)
		}
	}
}

func TestIsUserRecipientTag(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		{"recipient-alice-12345678", true},
		{"recipient-github-actions", false},
		{"secrets-default", false},
		{"user-alice", false},
	}

	for _, tt := range tests {
		if got := app.IsUserRecipientTag(tt.tag); got != tt.want {
			t.Errorf("IsUserRecipientTag(%q) = %v, want %v", tt.tag, got, tt.want)
		}
	}
}

func TestGitCommitInitFiles(t *testing.T) {
	client := &initTestGitClient{}
	err := gitCommitInitFiles(context.Background(), client, "C:/repo")
	if err != nil {
		t.Fatalf("gitCommitInitFiles: %v", err)
	}
	if client.commitPath != "C:/repo" || client.commitMessage != "chore: add enbu config" {
		t.Fatalf("commit = %q, %q", client.commitPath, client.commitMessage)
	}
	if strings.Join(client.commitFiles, ",") != "enbu.toml,.gitignore" {
		t.Fatalf("files = %v", client.commitFiles)
	}

	client.commitErr = errors.New("commit failed")
	if err := gitCommitInitFiles(context.Background(), client, "C:/repo"); err == nil {
		t.Fatal("expected commit error")
	}
}

type initTestGitClient struct {
	commitPath    string
	commitFiles   []string
	commitMessage string
	commitErr     error
}

func (*initTestGitClient) Inspect(context.Context, string) (gitprovider.Repository, error) {
	return gitprovider.Repository{}, nil
}

func (*initTestGitClient) Init(context.Context, string) error { return nil }

func (*initTestGitClient) AddRemote(context.Context, string, string, string) error { return nil }

func (c *initTestGitClient) CommitFiles(
	_ context.Context,
	path string,
	files []string,
	message string,
) error {
	c.commitPath = path
	c.commitFiles = append([]string(nil), files...)
	c.commitMessage = message
	return c.commitErr
}

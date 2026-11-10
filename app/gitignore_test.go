package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/config"
)

func writeGitignore(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ensureGitignoreIn(t *testing.T, dir string, cfg *config.ProjectConfig) string {
	t.Helper()
	if cfg == nil {
		cfg = &config.ProjectConfig{}
	}
	if err := (&App{RepositoryDir: dir}).ensureGitignore(cfg); err != nil {
		t.Fatalf("ensureGitignore: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEnsureGitignoreCreatesNewFile(t *testing.T) {
	content := ensureGitignoreIn(t, t.TempDir(), nil)
	for _, entry := range baseGitignoreEntries {
		if !strings.Contains(content, entry) {
			t.Errorf("missing entry %q in .gitignore", entry)
		}
	}
}

func TestEnsureGitignoreAppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	existing := "node_modules/\n*.log\n"
	writeGitignore(t, dir, existing)
	content := ensureGitignoreIn(t, dir, nil)
	if !strings.HasPrefix(content, existing) {
		t.Error("existing content was overwritten")
	}
	for _, entry := range baseGitignoreEntries {
		if !strings.Contains(content, entry) {
			t.Errorf("missing entry %q", entry)
		}
	}
}

func TestEnsureGitignoreNoDuplicates(t *testing.T) {
	dir := t.TempDir()
	existing := ".env\n.env.*\n!.env.example\n"
	writeGitignore(t, dir, existing)
	if content := ensureGitignoreIn(t, dir, nil); content != existing {
		t.Errorf("file was modified when all entries already exist:\ngot: %q\nwant: %q", content, existing)
	}
}

func TestEnsureGitignorePartialExisting(t *testing.T) {
	dir := t.TempDir()
	writeGitignore(t, dir, ".env\n")
	content := ensureGitignoreIn(t, dir, nil)
	if !strings.Contains(content, ".env.*") || !strings.Contains(content, "!.env.example") {
		t.Errorf("missing entries: %q", content)
	}
	if strings.Count(content, ".env\n") != 1 {
		t.Error(".env was duplicated")
	}
}

func TestEnsureGitignoreNoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	writeGitignore(t, dir, "node_modules/")
	if content := ensureGitignoreIn(t, dir, nil); !strings.HasPrefix(content, "node_modules/\n") {
		t.Error("newline not added after existing content without trailing newline")
	}
}

func TestEnsureGitignoreCustomOutputs(t *testing.T) {
	cfg := &config.ProjectConfig{Environments: map[string]config.EnvironmentConfig{
		"a": {Output: "secrets.json"},
		"b": {Output: "config/dev.env"},
		"c": {Output: "!literal.env"},
		"d": {Output: "/abs/path.env"},
	}}
	content := ensureGitignoreIn(t, t.TempDir(), cfg)
	for _, want := range []string{"secrets.json", "config/dev.env", `\!literal.env`} {
		if !strings.Contains(content, want) {
			t.Errorf("missing custom output %q in .gitignore", want)
		}
	}
	if strings.Contains(content, "/abs/path.env") {
		t.Error("an absolute output was added")
	}
}

func TestGitignoreLiteralMatchesOnlyThePath(t *testing.T) {
	for path, want := range map[string]string{
		"secrets.json":   "secrets.json",
		"!literal.env":   `\!literal.env`,
		"#hash.env":      `\#hash.env`,
		"out/*.env":      `out/\*.env`,
		"what?.env":      `what\?.env`,
		"[ab].env":       `\[ab].env`,
		`back\slash.env`: `back\\slash.env`,
	} {
		if got := gitignoreLiteral(path); got != want {
			t.Errorf("gitignoreLiteral(%q) = %q, want %q", path, got, want)
		}
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	if out, err := exec.Command(git, "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(gitignoreLiteral("out/*.env")+"\n"+gitignoreLiteral("[ab].env")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for path, ignored := range map[string]bool{"out/*.env": true, "out/x.env": false, "[ab].env": true, "a.env": false} {
		err := exec.Command(git, "-C", dir, "check-ignore", "-q", "--no-index", path).Run()
		if (err == nil) != ignored {
			t.Errorf("git check-ignore %q: ignored = %v, want %v", path, err == nil, ignored)
		}
	}
}

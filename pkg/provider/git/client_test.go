package git

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/pkg/fsutil"
)

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeGitDir lays out the files git init writes that Inspect reads.
func fakeGitDir(t *testing.T, gitDir, config string) {
	t.Helper()
	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(gitDir, "config"), config)
}

func inspect(t *testing.T, path string) Repository {
	t.Helper()
	repo, err := NewClient().Inspect(context.Background(), path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return repo
}

// A repository git init just made has no commit and no remote, and the app
// may not find the git command the person ran it with (GitHub Desktop brings
// its own); it is a repository all the same.
func TestInspectFreshRepositoryWithoutGitCommand(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	t.Setenv("PATH", "")

	repo := inspect(t, dir)
	if repo.Root != fsutil.Canonical(dir) || !repo.HasGit || repo.HasRemote || repo.OriginURL != "" {
		t.Fatalf("repository = %#v", repo)
	}
}

func TestInspectRepositoryFromSubfolder(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "remote", "add", "origin", "git@github.com:octo/example.git")
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	repo := inspect(t, sub)
	if repo.Root != fsutil.Canonical(dir) || !repo.HasGit || !repo.HasRemote {
		t.Fatalf("repository = %#v", repo)
	}
	if repo.OriginURL != "git@github.com:octo/example.git" {
		t.Fatalf("OriginURL = %q", repo.OriginURL)
	}
}

func TestInspectNonRepository(t *testing.T) {
	dir := t.TempDir()
	repo := inspect(t, dir)
	if repo.HasGit || repo.HasRemote || repo.Root != fsutil.Canonical(dir) {
		t.Fatalf("repository = %#v", repo)
	}
}

// A folder that only happens to be named .git is not a Git directory.
func TestInspectIgnoresEmptyDotGitFolder(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if repo := inspect(t, dir); repo.HasGit {
		t.Fatalf("repository = %#v", repo)
	}
}

// A worktree's .git is a file naming its Git directory, whose commondir
// leads to the config of the main repository.
func TestInspectWorktree(t *testing.T) {
	base := t.TempDir()
	mainGit := filepath.Join(base, "main", ".git")
	fakeGitDir(t, mainGit, "[remote \"origin\"]\n\turl = https://github.com/octo/hello.git\n")
	wtGit := filepath.Join(mainGit, "worktrees", "feature")
	writeFile(t, filepath.Join(wtGit, "HEAD"), "ref: refs/heads/feature\n")
	writeFile(t, filepath.Join(wtGit, "commondir"), "../..\n")
	worktree := filepath.Join(base, "feature")
	writeFile(t, filepath.Join(worktree, ".git"), "gitdir: "+filepath.ToSlash(wtGit)+"\n")

	repo := inspect(t, worktree)
	if repo.Root != fsutil.Canonical(worktree) || repo.OriginURL != "https://github.com/octo/hello.git" {
		t.Fatalf("repository = %#v", repo)
	}
}

// A submodule's .git file names its Git directory relative to itself.
func TestInspectRelativeGitFile(t *testing.T) {
	base := t.TempDir()
	fakeGitDir(t, filepath.Join(base, ".git", "modules", "lib"), "[remote \"origin\"]\n\turl = https://github.com/octo/lib.git\n")
	sub := filepath.Join(base, "lib")
	writeFile(t, filepath.Join(sub, ".git"), "gitdir: ../.git/modules/lib\r\n")

	repo := inspect(t, sub)
	if repo.Root != fsutil.Canonical(sub) || repo.OriginURL != "https://github.com/octo/lib.git" {
		t.Fatalf("repository = %#v", repo)
	}
}

func TestInspectRepositoryInNonASCIIPath(t *testing.T) {
	requireGit(t)
	dir := filepath.Join(t.TempDir(), "日本語 リポジトリ (テスト)")
	sub := filepath.Join(dir, "サブ フォルダ")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init")
	runGit(t, dir, "remote", "add", "origin", "https://github.com/octo/hello.git")

	repo := inspect(t, sub)
	if want := fsutil.Canonical(dir); repo.Root != want || !repo.HasGit || repo.OriginURL != "https://github.com/octo/hello.git" {
		t.Fatalf("repository = %#v, want root %q", repo, want)
	}
}

func TestInspectCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewClient().Inspect(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValue(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{"none", "[core]\n\tbare = false\n", ""},
		{"plain", "[remote \"origin\"]\n\turl = git@github.com:octo/a.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n", "git@github.com:octo/a.git"},
		{"other remote", "[remote \"upstream\"]\n\turl = https://github.com/up/a.git\n[remote \"origin\"]\n\turl = https://github.com/octo/a.git\n", "https://github.com/octo/a.git"},
		{"subsection is case sensitive", "[remote \"Origin\"]\n\turl = https://github.com/octo/a.git\n", ""},
		{"names ignore case", "[Remote \"origin\"]\n\tURL = https://github.com/octo/a.git\n", "https://github.com/octo/a.git"},
		{"quoted with comment", "[remote \"origin\"]\n\turl = \"https://github.com/octo/a b.git\" # mine\n", "https://github.com/octo/a b.git"},
		{"comment lines", "# top\n[remote \"origin\"]\n; old\n\turl=https://github.com/octo/a.git ; trailing\n", "https://github.com/octo/a.git"},
		{"last wins", "[remote \"origin\"]\n\turl = https://github.com/octo/old.git\n[remote \"origin\"]\n\turl = https://github.com/octo/new.git\n", "https://github.com/octo/new.git"},
		{"old header", "[remote.origin]\n\turl = https://github.com/octo/a.git\n", "https://github.com/octo/a.git"},
		{"key on header line", "[remote \"origin\"] url = https://github.com/octo/a.git\n", "https://github.com/octo/a.git"},
		{"crlf", "[remote \"origin\"]\r\n\turl = https://github.com/octo/a.git\r\n", "https://github.com/octo/a.git"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configValue([]byte(tt.config), "remote", "origin", "url"); got != tt.want {
				t.Fatalf("configValue = %q, want %q", got, tt.want)
			}
		})
	}
}

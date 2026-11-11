package git

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/fsutil"
)

type runResult struct {
	output string
	err    error
}

type recordedRun struct {
	dir  string
	args []string
}

type fakeRunner struct {
	results []runResult
	runs    []recordedRun
}

func (f *fakeRunner) Run(_ context.Context, dir string, args ...string) (string, error) {
	f.runs = append(f.runs, recordedRun{dir: dir, args: append([]string(nil), args...)})
	result := f.results[0]
	f.results = f.results[1:]
	return result.output, result.err
}

func TestInspectRepository(t *testing.T) {
	runner := &fakeRunner{results: []runResult{
		{output: "C:/repo"},
		{output: "git@github.com:octo/example.git"},
	}}
	client := &CLIClient{runner: runner}

	repo, err := client.Inspect(context.Background(), "C:/repo/subdir")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	root := fsutil.Canonical("C:/repo")
	if repo.Root != root || !repo.HasGit || !repo.HasRemote {
		t.Fatalf("repository = %#v", repo)
	}
	if repo.OriginURL != "git@github.com:octo/example.git" {
		t.Fatalf("OriginURL = %q", repo.OriginURL)
	}
	if got := runner.runs[1]; got.dir != root || !reflect.DeepEqual(got.args, []string{"remote", "get-url", "origin"}) {
		t.Fatalf("remote run = %#v", got)
	}
}

func TestInspectNonRepository(t *testing.T) {
	runner := &fakeRunner{results: []runResult{{err: errors.New("not a repository")}}}
	client := &CLIClient{runner: runner}

	repo, err := client.Inspect(context.Background(), ".")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if repo.HasGit || repo.HasRemote {
		t.Fatalf("repository = %#v", repo)
	}
}

// git runs in, and reports, a repository whose path holds Japanese and
// spaces; on Windows it prints the root with forward slashes, which Inspect
// turns into the spelling the CLI and the folder picker use.
func TestInspectRepositoryInNonASCIIPath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := filepath.Join(t.TempDir(), "日本語 リポジトリ (テスト)")
	sub := filepath.Join(dir, "サブ フォルダ")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	runner := ExecRunner{}
	for _, args := range [][]string{{"init"}, {"remote", "add", "origin", "https://github.com/octo/hello.git"}} {
		if _, err := runner.Run(context.Background(), dir, args...); err != nil {
			t.Fatal(err)
		}
	}
	repo, err := NewCLIClient().Inspect(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	if want := fsutil.Canonical(dir); repo.Root != want || !repo.HasGit || repo.OriginURL != "https://github.com/octo/hello.git" {
		t.Fatalf("repository = %#v, want root %q", repo, want)
	}
}

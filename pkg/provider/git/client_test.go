package git

import (
	"context"
	"errors"
	"reflect"
	"testing"
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
	client := NewCLIClientWithRunner(runner)

	repo, err := client.Inspect(context.Background(), "C:/repo/subdir")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if repo.Root != "C:/repo" || !repo.HasGit || !repo.HasRemote {
		t.Fatalf("repository = %#v", repo)
	}
	if repo.OriginURL != "git@github.com:octo/example.git" {
		t.Fatalf("OriginURL = %q", repo.OriginURL)
	}
	if got := runner.runs[1]; got.dir != "C:/repo" || !reflect.DeepEqual(got.args, []string{"remote", "get-url", "origin"}) {
		t.Fatalf("remote run = %#v", got)
	}
}

func TestInspectNonRepository(t *testing.T) {
	runner := &fakeRunner{results: []runResult{{err: errors.New("not a repository")}}}
	client := NewCLIClientWithRunner(runner)

	repo, err := client.Inspect(context.Background(), ".")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if repo.HasGit || repo.HasRemote {
		t.Fatalf("repository = %#v", repo)
	}
}

func TestInitAndAddRemote(t *testing.T) {
	runner := &fakeRunner{results: []runResult{{}, {}}}
	client := NewCLIClientWithRunner(runner)

	if err := client.Init(context.Background(), "C:/repo"); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.AddRemote(context.Background(), "C:/repo", "origin", "https://github.com/octo/example.git"); err != nil {
		t.Fatalf("AddRemote: %v", err)
	}
	want := []recordedRun{
		{dir: "C:/repo", args: []string{"init"}},
		{dir: "C:/repo", args: []string{"remote", "add", "origin", "https://github.com/octo/example.git"}},
	}
	if !reflect.DeepEqual(runner.runs, want) {
		t.Fatalf("runs = %#v, want %#v", runner.runs, want)
	}
}

func TestCommitFiles(t *testing.T) {
	runner := &fakeRunner{results: []runResult{{}, {}}}
	client := NewCLIClientWithRunner(runner)

	err := client.CommitFiles(
		context.Background(),
		"C:/repo",
		[]string{"enbu.toml", ".gitignore"},
		"chore: add enbu config",
	)
	if err != nil {
		t.Fatalf("CommitFiles: %v", err)
	}
	want := []recordedRun{
		{dir: "C:/repo", args: []string{"add", "--", "enbu.toml", ".gitignore"}},
		{dir: "C:/repo", args: []string{"commit", "-m", "chore: add enbu config"}},
	}
	if !reflect.DeepEqual(runner.runs, want) {
		t.Fatalf("runs = %#v, want %#v", runner.runs, want)
	}
}

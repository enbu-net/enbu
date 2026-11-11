package git

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/fsutil"
	"github.com/enbu-net/enbu/pkg/process"
)

type Repository struct {
	Root      string
	OriginURL string
	HasGit    bool
	HasRemote bool
}

type Client interface {
	Inspect(ctx context.Context, path string) (Repository, error)
}

type Runner interface {
	Run(ctx context.Context, dir string, args ...string) (string, error)
}

type CLIClient struct {
	runner Runner
}

func NewCLIClient() *CLIClient {
	return &CLIClient{runner: ExecRunner{}}
}

func (c *CLIClient) Inspect(ctx context.Context, path string) (Repository, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Repository{}, fmt.Errorf("resolving repository path: %w", err)
	}
	repository := Repository{Root: fsutil.Canonical(abs)}

	root, err := c.runner.Run(ctx, abs, "rev-parse", "--show-toplevel")
	if err != nil {
		return repository, nil
	}
	// git prints forward slashes on Windows; the root becomes the same
	// spelling as a path the CLI or a folder picker resolved.
	repository.Root = fsutil.Canonical(root)
	repository.HasGit = true

	remote, err := c.runner.Run(ctx, repository.Root, "remote", "get-url", "origin")
	if err == nil {
		repository.OriginURL = remote
		repository.HasRemote = true
	}
	return repository, nil
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	process.HideWindow(cmd)
	cmd.Dir = dir
	// stdout only: a warning git prints on stderr is not part of a path.
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		output := ""
		if errors.As(err, &exit) {
			output = strings.TrimSpace(string(exit.Stderr))
		}
		if output == "" {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("git %s: %s: %w", strings.Join(args, " "), output, err)
	}
	// Only the line break goes: a folder name may end in a space.
	return strings.TrimRight(string(out), "\r\n"), nil
}

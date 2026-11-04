package git

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

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

func NewCLIClientWithRunner(runner Runner) *CLIClient {
	return &CLIClient{runner: runner}
}

func (c *CLIClient) Inspect(ctx context.Context, path string) (Repository, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Repository{}, fmt.Errorf("resolving repository path: %w", err)
	}
	repository := Repository{Root: abs}

	root, err := c.runner.Run(ctx, abs, "rev-parse", "--show-toplevel")
	if err != nil {
		return repository, nil
	}
	repository.Root = root
	repository.HasGit = true

	remote, err := c.runner.Run(ctx, root, "remote", "get-url", "origin")
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
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output == "" {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("git %s: %s: %w", strings.Join(args, " "), output, err)
	}
	return output, nil
}

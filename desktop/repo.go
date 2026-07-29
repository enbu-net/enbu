package desktop

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/config"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
)

type SelectedRepo struct {
	Path      string `json:"path,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Repo      string `json:"repo,omitempty"`
	HasGit    bool   `json:"has_git"`
	HasRemote bool   `json:"has_remote"`
}

func ValidateRepoPath(path string) (*SelectedRepo, error) {
	return validateRepoPath(context.Background(), gitprovider.NewCLIClient(), path)
}

func validateRepoPath(
	ctx context.Context,
	gitClient gitprovider.Client,
	path string,
) (*SelectedRepo, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("reading path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path must be a directory")
	}

	repository, err := gitClient.Inspect(ctx, abs)
	if err != nil {
		return nil, fmt.Errorf("inspecting git repository: %w", err)
	}

	var owner, repo string
	if repository.HasRemote {
		owner, repo, _ = config.ParseGitRemote(repository.OriginURL)
	}

	return &SelectedRepo{
		Path:      repository.Root,
		Owner:     owner,
		Repo:      repo,
		HasGit:    repository.HasGit,
		HasRemote: repository.HasRemote,
	}, nil
}

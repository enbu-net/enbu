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
	HasRemote bool   `json:"has_remote"`
}

func validateRepoPath(
	ctx context.Context,
	gitClient gitprovider.Client,
	path string,
) (*SelectedRepo, error) {
	// A folder name may begin or end with a space, so the path is not trimmed.
	if strings.TrimSpace(path) == "" {
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
		owner, repo, _ = config.ParseGitHubRemote(repository.OriginURL)
	}

	return &SelectedRepo{
		Path:      repository.Root,
		Owner:     owner,
		Repo:      repo,
		HasRemote: repository.HasRemote,
	}, nil
}

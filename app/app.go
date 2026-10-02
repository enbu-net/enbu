package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/oci"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
)

type App struct {
	Registry      Registry
	TokenProvider TokenProvider
	Identities    IdentityStore
	RepoDetector  RepoDetector
	Git           gitprovider.Client
	Platform      PlatformClient
	Events        EventHandler
	RegistryHost  string
	RepositoryDir string
}

func (a *App) SetRepositoryDir(dir string) {
	a.RepositoryDir = dir
	if detector, ok := a.RepoDetector.(*defaultRepoDetector); ok {
		detector.dir = dir
	}
}

func (a *App) loadProject() (*config.ProjectConfig, error) {
	return config.LoadProjectFrom(a.RepositoryDir)
}

func (a *App) saveProject(cfg *config.ProjectConfig) error {
	return config.SaveProjectTo(a.RepositoryDir, cfg)
}

func (a *App) loadLocal() (*config.LocalConfig, error) {
	if a.RepoDetector == nil {
		return &config.LocalConfig{}, nil
	}
	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return &config.LocalConfig{}, nil
	}
	return config.LoadLocalState(owner, repo)
}

func (a *App) saveLocal(cfg *config.LocalConfig) error {
	if a.RepoDetector == nil {
		return nil
	}
	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return err
	}
	return config.SaveLocalState(owner, repo, cfg)
}

func (a *App) registryHost() string {
	if a.RegistryHost != "" {
		return a.RegistryHost
	}
	return "ghcr.io"
}

func (a *App) registryRef(owner, repo string) string {
	return fmt.Sprintf("%s/%s/%s-enbu", a.registryHost(), strings.ToLower(owner), strings.ToLower(repo))
}

func (a *App) secretsRef(owner, repo, env string) string {
	return a.registryRef(owner, repo) + ":" + secretsTag(env)
}

func (a *App) emit(msg string) {
	if a.Events != nil {
		a.Events.OnProgress(msg)
	}
}

func (a *App) emitRetry(attempt, max int) {
	if a.Events != nil {
		a.Events.OnConflictRetry(attempt, max)
	}
}

func (a *App) emitStepProgress(op, step, status string) {
	if a.Events != nil {
		a.Events.OnStepProgress(ProgressStep{
			Op:     op,
			Step:   step,
			Status: status,
		})
	}
}

func New() *App {
	gitClient := gitprovider.NewCLIClient()
	return &App{
		Registry:      &defaultRegistry{},
		TokenProvider: &defaultTokenProvider{},
		Identities:    identity.New(),
		RepoDetector:  &defaultRepoDetector{git: gitClient},
		Git:           gitClient,
	}
}

type defaultRegistry struct{}

func (d *defaultRegistry) Push(ctx context.Context, ref string, mediaType string, data []byte, token string, opts *oci.PushOptions) error {
	return oci.Push(ctx, ref, mediaType, data, token, opts)
}

func (d *defaultRegistry) Pull(ctx context.Context, ref string, token string) ([]byte, error) {
	return oci.Pull(ctx, ref, token)
}

func (d *defaultRegistry) ListTags(ctx context.Context, ref string, token string) ([]string, error) {
	return oci.ListTags(ctx, ref, token)
}

func (d *defaultRegistry) GetDigest(ctx context.Context, ref string, token string) (string, error) {
	return oci.GetDigest(ctx, ref, token)
}

type defaultTokenProvider struct{}

func (d *defaultTokenProvider) LoadToken() (string, string, error) {
	token, err := auth.LoadToken()
	if err != nil {
		return "", "", err
	}
	return token.AccessToken, token.Username, nil
}

type defaultRepoDetector struct {
	git gitprovider.Client
	dir string
}

func (d *defaultRepoDetector) LoadRepo() (string, string, error) {
	dir := d.dir
	if dir == "" {
		dir = "."
	}
	repository, err := d.git.Inspect(context.Background(), dir)
	if err != nil {
		return "", "", err
	}
	if !repository.HasRemote {
		return "", "", fmt.Errorf("git remote not found")
	}
	return config.ParseGitRemote(repository.OriginURL)
}

func (a *App) sourceRepoURL(owner, repo string) string {
	if a.Platform != nil {
		return a.Platform.SourceRepoURL(owner, repo)
	}
	return fmt.Sprintf("https://github.com/%s/%s", owner, repo)
}

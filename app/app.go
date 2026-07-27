package app

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/enbu-net/enbu/auth"
	"github.com/enbu-net/enbu/config"
	gitprovider "github.com/enbu-net/enbu/provider/git"
	"github.com/enbu-net/enbu/utils/keystore"
	"github.com/enbu-net/enbu/utils/oci"
)

type App struct {
	Registry      Registry
	TokenProvider TokenProvider
	KeyStore      KeyStore
	SecretCache   SecretCache
	RepoDetector  RepoDetector
	Git           gitprovider.Client
	Platform      PlatformClient
	Events        EventHandler
	RegistryHost  string
	RepositoryDir string
	fallbackCache SecretCache
	fallbackOnce  sync.Once
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
	return config.LoadLocalFrom(a.RepositoryDir)
}

func (a *App) saveLocal(cfg *config.LocalConfig) error {
	return config.SaveLocalTo(a.RepositoryDir, cfg)
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
	ks, err := keystore.New()
	var keystoreImpl KeyStore
	if err != nil {
		keystoreImpl = &unavailableKeyStore{err: fmt.Errorf("initializing keystore: %w", err)}
	} else {
		keystoreImpl = &defaultKeyStore{backend: ks}
	}
	return &App{
		Registry:      &defaultRegistry{},
		TokenProvider: &defaultTokenProvider{},
		KeyStore:      keystoreImpl,
		SecretCache:   newFileSecretCache(),
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

type defaultKeyStore struct {
	backend keystore.Backend
}

func (d *defaultKeyStore) Store(service, key string, value []byte) error {
	return d.backend.Store(service, key, value)
}

func (d *defaultKeyStore) Load(service, key string) ([]byte, error) {
	return d.backend.Load(service, key)
}

type unavailableKeyStore struct {
	err error
}

func (u *unavailableKeyStore) Store(_, _ string, _ []byte) error {
	return u.err
}

func (u *unavailableKeyStore) Load(_, _ string) ([]byte, error) {
	return nil, u.err
}

func (a *App) sourceRepoURL(owner, repo string) string {
	if a.Platform != nil {
		return a.Platform.SourceRepoURL(owner, repo)
	}
	return fmt.Sprintf("https://github.com/%s/%s", owner, repo)
}

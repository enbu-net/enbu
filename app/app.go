package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"uuid"

	"github.com/enbu-net/enbu/pkg/apperr"
	"oras.land/oras-go/v2/registry/remote/auth"

	enbuauth "github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/winbridge"
)

type App struct {
	// Runtime supplies per-instance external dependencies. Nil uses production defaults.
	Runtime *Runtime

	Storage       storage.Store
	StorageURL    string
	TokenProvider TokenProvider
	Identities    IdentityStore
	RepoDetector  RepoDetector
	Git           gitprovider.Client
	Events        EventHandler
	RepositoryDir string
	// CheckpointDir holds the local rollback checkpoints. Empty means the
	// per-user data directory.
	CheckpointDir string
	// CacheDir holds what this device keeps to avoid fetching again: heads of
	// stored revisions and the history index. Empty means the per-user data
	// directory. Nothing in it is trusted or secret.
	CacheDir string
}

func (a *App) cacheDir() string {
	if a.CacheDir != "" {
		return a.CacheDir
	}
	return filepath.Join(config.DataDir(), "cache")
}

func (a *App) SetRepositoryDir(dir string) {
	a.RepositoryDir = dir
	if detector, ok := a.RepoDetector.(*defaultRepoDetector); ok {
		detector.dir = dir
	}
}

// loadProject reads enbu.toml and the environment this user switched to.
func (a *App) loadProject() (*config.ProjectConfig, error) {
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		return nil, err
	}
	if _, perr := uuid.Parse(cfg.WorkspaceID); perr == nil {
		// A broken local state must not silently send commands to the team default.
		local, err := a.loadLocalState(cfg.WorkspaceID)
		if err != nil {
			return nil, err
		}
		cfg.Current = local.Current
	}
	return cfg, nil
}

func (a *App) saveProject(cfg *config.ProjectConfig) error {
	if err := config.ValidateProjectOutputs(cfg); err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "invalid project configuration", err, nil)
	}
	return config.SaveProjectTo(a.RepositoryDir, cfg)
}

func (a *App) loadLocal() (*config.LocalConfig, error) {
	id, err := a.WorkspaceID()
	if err != nil {
		return nil, err
	}
	return a.loadLocalState(id)
}
func (a *App) WorkspaceID() (id string, err error) {
	defer apperr.NormalizeInto(&err)
	cfg, err := a.loadProject()
	if err != nil {
		return "", err
	}
	if _, err := uuid.Parse(cfg.WorkspaceID); err != nil {
		return "", apperr.New(apperr.CodeNotInitialized, "invalid or missing workspace ID (run enbu init)", nil)
	}
	return cfg.WorkspaceID, nil
}

func (a *App) openStorage(ctx context.Context, cfg *config.ProjectConfig) (storage.Store, error) {
	if a.Storage != nil {
		return a.Storage, nil
	}
	settings := cfg.Storage
	if a.StorageURL != "" {
		settings.URL = a.StorageURL
	}
	u, err := url.Parse(settings.URL)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "storage URL cannot contain credentials, query or fragment", nil)
	}
	switch u.Scheme {
	case "local":
		return openLocalStorage(u)
	case "s3":
		if u.Host == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument, "S3 storage requires a bucket", nil)
		}
		client, err := storage.NewS3Client(settings.Endpoint, settings.Region, settings.PathStyle)
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeInvalidArgument, "invalid S3 configuration", err, nil)
		}
		return storage.NewS3(client, u.Host, strings.Trim(u.Path, "/")), nil
	case "oci":
		// ghcr.io uses enbu's GitHub login; any other registry uses the Docker
		// credential configuration.
		credential := a.ociCredential(u.Host)
		if u.Host == "ghcr.io" {
			// Deleting needs the GitHub Packages API, which the same token can reach.
			return storage.NewGHCR(u.Host+u.Path, credential, func() (string, error) {
				token, _, err := a.TokenProvider.LoadToken()
				return token, err
			})
		}
		return storage.NewOCI(u.Host+u.Path, credential, settings.PlainHTTP)
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument, "storage must be specified with oci:// or s3://", nil)
	}
}

// ociCredential is the credential for an OCI registry host: enbu's GitHub
// login for ghcr.io, or nil, which makes the OCI store read the Docker
// credential configuration.
func (a *App) ociCredential(registry string) auth.CredentialFunc {
	if registry != "ghcr.io" {
		return nil
	}
	return func(_ context.Context, host string) (auth.Credential, error) {
		if host != "ghcr.io" {
			return auth.EmptyCredential, nil
		}
		if a.TokenProvider == nil {
			return auth.EmptyCredential, apperr.New(apperr.CodeNotAuthenticated, "GitHub credentials unavailable", nil)
		}
		token, username, err := a.TokenProvider.LoadToken()
		if err != nil {
			return auth.EmptyCredential, apperr.Wrap(apperr.CodeNotAuthenticated, "ghcr.io storage uses enbu's GitHub login; run 'enbu auth login'", err, nil)
		}
		return auth.Credential{Username: username, Password: token}, nil
	}
}

func (a *App) workspaceStorage(ctx context.Context, cfg *config.ProjectConfig) (storage.Store, error) {
	if _, err := uuid.Parse(cfg.WorkspaceID); err != nil {
		return nil, apperr.New(apperr.CodeNotInitialized, "workspace ID missing or invalid", nil)
	}
	store, err := a.openStorage(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return storage.WithHeadCache(store, filepath.Join(a.cacheDir(), "heads")), nil
}

func storageError(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return apperr.Wrap(apperr.CodeArtifactNotFound, "storage object not found", err, nil)
	case errors.Is(err, storage.ErrCorrupt):
		return apperr.Wrap(apperr.CodeUntrusted, "stored data does not match its name", err, nil)
	case errors.Is(err, storage.ErrUnsupported):
		return apperr.Wrap(apperr.CodeInvalidArgument, "this storage cannot delete stored revisions", err, nil)
	default:
		return err
	}
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

func New(c clock.Clock) *App {
	gitClient := gitprovider.NewClient()
	return &App{
		TokenProvider: &defaultTokenProvider{},
		Runtime:       &Runtime{Clock: c},
		Identities:    identityStore(c),
		RepoDetector:  &defaultRepoDetector{git: gitClient},
		Git:           gitClient,
	}
}

// identityStore keeps keys in this OS, or inside WSL in Windows: WSL never
// uses the Linux keystore, so its keys get the Windows TPM and Hello.
func identityStore(c clock.Clock) IdentityStore {
	if winbridge.InWSL() {
		return winbridge.Shared()
	}
	return identity.New(c)
}

type defaultTokenProvider struct{}

func (d *defaultTokenProvider) LoadToken() (string, string, error) {
	token, err := enbuauth.LoadToken()
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
	return config.ParseGitHubRemote(repository.OriginURL)
}

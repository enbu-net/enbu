package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/enbu-net/enbu/pkg/apperr"
	"net/url"
	"oras.land/oras-go/v2/registry/remote/auth"
	"strings"
	"uuid"

	enbuauth "github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
	"github.com/enbu-net/enbu/pkg/storage"
)

type App struct {
	Storage       storage.Store
	StorageURL    string
	InitStorage   *config.StorageConfig
	TokenProvider TokenProvider
	Identities    IdentityStore
	RepoDetector  RepoDetector
	Git           gitprovider.Client
	Platform      PlatformClient
	Events        EventHandler
	RepositoryDir string
	// CheckpointDir holds the local rollback checkpoints. Empty means the
	// per-user data directory.
	CheckpointDir string
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
	id, err := a.WorkspaceID()
	if err != nil {
		return nil, err
	}
	return config.LoadLocalState(id)
}
func (a *App) saveLocal(cfg *config.LocalConfig) error {
	id, err := a.WorkspaceID()
	if err != nil {
		return err
	}
	return config.SaveLocalState(id, cfg)
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
		var credential auth.CredentialFunc
		switch settings.OCIAuth {
		case "", "docker":
		case "github":
			if u.Host != "ghcr.io" {
				return nil, apperr.New(apperr.CodeInvalidArgument, "GitHub authentication is only supported for ghcr.io", nil)
			}
			credential = func(_ context.Context, host string) (auth.Credential, error) {
				if host != "ghcr.io" {
					return auth.EmptyCredential, nil
				}
				token, username, err := a.TokenProvider.LoadToken()
				return auth.Credential{Username: username, Password: token}, err
			}
		default:
			return nil, apperr.New(apperr.CodeInvalidArgument, "invalid OCI authentication mode", nil)
		}
		var opts []storage.OCIOption
		if settings.OCIAuth == "github" {
			// Deleting needs the GitHub Packages API, which the same token can reach.
			if g, ok := storage.GHCRPackagesFor(u.Host+u.Path, func() (string, error) {
				token, _, err := a.TokenProvider.LoadToken()
				return token, err
			}); ok {
				opts = append(opts, storage.WithTagDeleter(g))
			}
		}
		return storage.NewOCI(u.Host+u.Path, credential, settings.PlainHTTP, opts...)
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument, "storage must be specified with oci:// or s3://", nil)
	}
}

func (a *App) workspaceStorage(ctx context.Context) (storage.Store, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return nil, err
	}
	if _, err := uuid.Parse(cfg.WorkspaceID); err != nil {
		return nil, apperr.New(apperr.CodeNotInitialized, "workspace ID missing or invalid", nil)
	}
	return a.openStorage(ctx, cfg)
}

func storageError(err error) error {
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return apperr.Wrap(apperr.CodeArtifactNotFound, "storage object not found", err, nil)
	case errors.Is(err, storage.ErrCorrupt):
		return apperr.Wrap(apperr.CodeUntrusted, "stored data does not match its name", err, nil)
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

func New() *App {
	gitClient := gitprovider.NewCLIClient()
	return &App{
		TokenProvider: &defaultTokenProvider{},
		Identities:    identity.New(),
		RepoDetector:  &defaultRepoDetector{git: gitClient},
		Git:           gitClient,
	}
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
	return config.ParseGitRemote(repository.OriginURL)
}

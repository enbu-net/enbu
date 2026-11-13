package app

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func TestStorageErrorClassifiesRegistryForbidden(t *testing.T) {
	cause := &errcode.ErrorResponse{Method: "GET", URL: &url.URL{Scheme: "https", Host: "ghcr.io"}, StatusCode: http.StatusForbidden}
	err := storageError(cause)
	if !apperr.Is(err, apperr.CodeAccessDenied) || !errors.Is(err, cause) {
		t.Fatalf("403 must preserve cause and report access denied: %v", err)
	}
}

type failingRepoDetector struct{}

func (failingRepoDetector) LoadRepo() (string, string, error) {
	return "", "", errors.New("git remote not found")
}

func newFreshApp(t *testing.T, detector RepoDetector) *App {
	t.Helper()
	return &App{Storage: newMemRegistry(), Identities: &apptest.Identities{}, RepoDetector: detector,
		RepositoryDir: t.TempDir(), CheckpointDir: t.TempDir()}
}

// A new workspace in a GitHub repository needs no storage flag: it is stored
// on GHCR beside the repository, and enbu.toml keeps that choice.
func TestInitializeDefaultsToGHCRBesideTheGitHubRepository(t *testing.T) {
	a := newFreshApp(t, &staticRepoDetector{owner: "Enbu-Net", repo: "My.App"})
	result, err := a.InitializeRepository(context.Background(), InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "oci://ghcr.io/enbu-net/my.app-enbu"
	if result.Storage != want || !result.Founded {
		t.Fatalf("storage %q founded %v, want %q founded", result.Storage, result.Founded, want)
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil || cfg.Storage.URL != want {
		t.Fatalf("enbu.toml storage %q %v, want %q", cfg.Storage.URL, err, want)
	}

	// Once written, the storage is never derived again: another remote does not move it.
	a.RepoDetector = &staticRepoDetector{owner: "fork", repo: "app"}
	again, err := a.InitializeRepository(context.Background(), InitOptions{})
	if err != nil || again.Storage != want || again.Founded {
		t.Fatalf("second init: storage %q founded %v %v", again.Storage, again.Founded, err)
	}
}

func TestInitializeWithoutStorageOutsideGitHubFails(t *testing.T) {
	a := newFreshApp(t, failingRepoDetector{})
	if _, err := a.InitializeRepository(context.Background(), InitOptions{}); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("init without storage or GitHub remote: %v", err)
	}
	if _, err := config.LoadProjectFrom(a.RepositoryDir); !apperr.Is(err, apperr.CodeConfigNotFound) {
		t.Fatalf("a failed init wrote enbu.toml: %v", err)
	}
}

func TestInitializeExplicitStorageSkipsTheDefault(t *testing.T) {
	a := newFreshApp(t, failingRepoDetector{})
	a.StorageURL = "oci://registry.example.com/team/secrets"
	result, err := a.InitializeRepository(context.Background(), InitOptions{})
	if err != nil || result.Storage != a.StorageURL {
		t.Fatalf("storage %q %v, want %q", result.Storage, err, a.StorageURL)
	}
}

// GitHub allows repository names that OCI does not; those need --storage.
func TestInitializeRejectsAGitHubNameGHCRCannotHold(t *testing.T) {
	a := newFreshApp(t, &staticRepoDetector{owner: "enbu-net", repo: ".github"})
	if _, err := a.InitializeRepository(context.Background(), InitOptions{}); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("init with an OCI-invalid repository name: %v", err)
	}
	if _, err := config.LoadProjectFrom(a.RepositoryDir); !apperr.Is(err, apperr.CodeConfigNotFound) {
		t.Fatalf("a failed init wrote enbu.toml: %v", err)
	}
}

type failingTokenProvider struct{}

func (failingTokenProvider) LoadToken() (string, string, error) {
	return "", "", errors.New("no token stored")
}

// ghcr.io always uses enbu's GitHub login; other registries use the Docker
// credential configuration (a nil credential).
func TestOCICredentialFollowsTheHost(t *testing.T) {
	ctx := context.Background()
	a := &App{TokenProvider: &staticTokenProvider{token: "tok", username: "alice"}}
	if cred := a.ociCredential("registry.example.com"); cred != nil {
		t.Fatal("a non-GHCR registry got enbu's GitHub login")
	}
	cred := a.ociCredential("ghcr.io")
	got, err := cred(ctx, "ghcr.io")
	if err != nil || got.Username != "alice" || got.Password != "tok" {
		t.Fatalf("ghcr.io credential %+v %v", got, err)
	}
	if got, err := cred(ctx, "registry.example.com"); err != nil || got.Password != "" {
		t.Fatalf("the GitHub token was offered to another host: %+v %v", got, err)
	}

	a.TokenProvider = failingTokenProvider{}
	if _, err := a.ociCredential("ghcr.io")(ctx, "ghcr.io"); !apperr.Is(err, apperr.CodeNotAuthenticated) {
		t.Fatalf("ghcr.io without a login: %v", err)
	}
}

func TestDefaultStorageUsesSignedInAccountWithoutGit(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"My App", "my-app"}, {"日本語", "workspace"}, {".config", "config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newFreshApp(t, failingRepoDetector{})
			a.RepositoryDir = filepath.Join(t.TempDir(), tc.name)
			a.TokenProvider = &staticTokenProvider{token: "tok", username: "Octo"}
			got, err := a.DefaultStorageURL()
			if want := "oci://ghcr.io/octo/" + tc.want + "-enbu"; err != nil || got != want {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestDefaultStorageWithoutGitRequiresAccount(t *testing.T) {
	a := newFreshApp(t, failingRepoDetector{})
	a.TokenProvider = failingTokenProvider{}
	if _, err := a.DefaultStorageURL(); !apperr.Is(err, apperr.CodeNotAuthenticated) {
		t.Fatalf("got %v", err)
	}
}

func TestInitializeWithoutGitDefaultsToAccountGHCR(t *testing.T) {
	a := newFreshApp(t, failingRepoDetector{})
	a.TokenProvider = &staticTokenProvider{token: "tok", username: "octo"}
	want, err := a.DefaultStorageURL()
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.InitializeRepository(context.Background(), InitOptions{})
	if err != nil || result.Storage != want || !result.Founded {
		t.Fatalf("got %+v, %v", result, err)
	}
}

func TestDefaultStorageUsesWorkingDirectoryWhenRepositoryDirIsEmpty(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "My Project")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	for _, path := range []string{"", ".", filepath.Join("..", "My Project")} {
		a := newFreshApp(t, failingRepoDetector{})
		a.RepositoryDir = path
		a.TokenProvider = &staticTokenProvider{token: "tok", username: "octo"}
		got, err := a.DefaultStorageURL()
		if err != nil || got != "oci://ghcr.io/octo/my-project-enbu" {
			t.Fatalf("path %q: %q %v", path, got, err)
		}
	}
}

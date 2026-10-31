package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

type failingRepoDetector struct{}

func (failingRepoDetector) LoadRepo() (string, string, error) {
	return "", "", errors.New("git remote not found")
}

func newFreshApp(t *testing.T, detector RepoDetector) *App {
	t.Helper()
	return &App{Storage: newMemRegistry(), Identities: newMemKeyStore(), RepoDetector: detector,
		RepositoryDir: t.TempDir(), CheckpointDir: t.TempDir()}
}

// A new workspace in a GitHub repository needs no storage flag: it is stored
// on GHCR beside the repository, and enbu.toml keeps that choice.
func TestInitializeDefaultsToGHCRBesideTheGitHubRepository(t *testing.T) {
	a := newFreshApp(t, &staticRepoDetector{owner: "Enbu-Net", repo: "My.App"})
	result, err := a.InitializeRepository(context.Background())
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
	again, err := a.InitializeRepository(context.Background())
	if err != nil || again.Storage != want || again.Founded {
		t.Fatalf("second init: storage %q founded %v %v", again.Storage, again.Founded, err)
	}
}

func TestInitializeWithoutStorageOutsideGitHubFails(t *testing.T) {
	a := newFreshApp(t, failingRepoDetector{})
	if _, err := a.InitializeRepository(context.Background()); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("init without storage or GitHub remote: %v", err)
	}
	if _, err := config.LoadProjectFrom(a.RepositoryDir); !apperr.Is(err, apperr.CodeConfigNotFound) {
		t.Fatalf("a failed init wrote enbu.toml: %v", err)
	}
}

func TestInitializeExplicitStorageSkipsTheDefault(t *testing.T) {
	a := newFreshApp(t, failingRepoDetector{})
	a.StorageURL = "oci://registry.example.com/team/secrets"
	result, err := a.InitializeRepository(context.Background())
	if err != nil || result.Storage != a.StorageURL {
		t.Fatalf("storage %q %v, want %q", result.Storage, err, a.StorageURL)
	}
}

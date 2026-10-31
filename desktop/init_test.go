package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
)

func newInitService(t *testing.T, dir string) *Service {
	t.Helper()
	a := app.New()
	a.Identities = &desktopKeyStore{values: map[string][]byte{}}
	a.CheckpointDir = t.TempDir()
	s := NewService(a)
	s.repoPath = dir
	return s
}

// The GUI founds a workspace in the storage it is given, and a second device
// that receives the enbu.toml joins it as `enbu init` does.
func TestInitializeFoundsAndJoinsWorkspace(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	url := "local:///" + strings.TrimPrefix(filepath.ToSlash(t.TempDir()), "/")
	aliceDir := t.TempDir()
	alice := newInitService(t, aliceDir)

	founded, err := alice.Initialize(StorageSettings{URL: url}, false)
	if err != nil || !founded.Founded || founded.Pending || founded.Storage != url {
		t.Fatalf("found: %+v %v", founded, err)
	}
	shared, err := os.ReadFile(filepath.Join(aliceDir, "enbu.toml"))
	if err != nil {
		t.Fatal(err)
	}

	bobDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(bobDir, "enbu.toml"), shared, 0o644); err != nil {
		t.Fatal(err)
	}
	bob := newInitService(t, bobDir)
	if _, err := bob.Initialize(StorageSettings{URL: url}, false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("a storage was accepted beside an enbu.toml: %v", err)
	}
	joined, err := bob.Initialize(StorageSettings{}, false)
	if err != nil || joined.Founded || !joined.Pending || joined.Storage != url {
		t.Fatalf("join: %+v %v", joined, err)
	}
}

// Without a GitHub origin there is no storage to suggest.
func TestSuggestStorageNeedsGitHubOrigin(t *testing.T) {
	s := newInitService(t, t.TempDir())
	if _, err := s.SuggestStorage(); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("suggest: %v", err)
	}
}

// An enbu.toml that names no storage yet still takes the one the person enters.
func TestInitializeTakesStorageBesideStoragelessConfig(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	url := "local:///" + strings.TrimPrefix(filepath.ToSlash(t.TempDir()), "/")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte("version = \"v1alpha2\"\nworkspace_id = \"3f2b8c1e-9a4d-4e6b-8c2f-1a5d7e9b0c3d\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := newInitService(t, dir).Initialize(StorageSettings{URL: url}, false)
	if err != nil || !result.Founded || result.Storage != url {
		t.Fatalf("found: %+v %v", result, err)
	}
}

// acceptNewGenesis reaches the app: with no control_genesis in enbu.toml
// there is no new root to accept.
func TestInitializeForwardsAcceptNewGenesis(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	url := "local:///" + strings.TrimPrefix(filepath.ToSlash(t.TempDir()), "/")
	s := newInitService(t, t.TempDir())
	if _, err := s.Initialize(StorageSettings{URL: url}, true); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("accepted a new root without one: %v", err)
	}
	if s.app.AcceptNewGenesis || s.app.InitStorage != nil {
		t.Fatalf("init overrides outlived the call: %v %v", s.app.AcceptNewGenesis, s.app.InitStorage)
	}
}

// With a GitHub origin the suggestion is the GHCR package `enbu init` picks.
func TestSuggestStorageFromGitHubOrigin(t *testing.T) {
	s := newInitService(t, newGitRepo(t))
	if got, err := s.SuggestStorage(); err != nil || got != "oci://ghcr.io/octo/hello-enbu" {
		t.Fatalf("suggest: %q %v", got, err)
	}
}

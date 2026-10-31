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

	founded, err := alice.Initialize(url, false)
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
	if _, err := bob.Initialize(url, false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("a storage was accepted beside an enbu.toml: %v", err)
	}
	joined, err := bob.Initialize("", false)
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

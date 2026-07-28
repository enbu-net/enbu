package auth

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/utils/keystore"
)

// stubBackend replaces tokenBackend with an in-memory store for the duration of the test.
func stubBackend(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("ENBU_TEXT_BACKEND_DIR", dir)
	orig := tokenBackend
	tokenBackend = &keystore.TextBackend{}
	t.Cleanup(func() { tokenBackend = orig })
}

func TestTokenStoreRoundTripAndLegacyCleanup(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataDir)
	stubBackend(t)

	legacy := filepath.Join(dataDir, "enbu", "token.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("legacy-secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	want := &StoredToken{AccessToken: "token", Username: "octo", UserID: 123}
	if err := SaveToken(want); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy token still exists: %v", err)
	}
	got, err := LoadToken()
	if err != nil || *got != *want {
		t.Fatalf("LoadToken = %#v, %v", got, err)
	}

	renamed := &StoredToken{AccessToken: "new-token", Username: "renamed-octo", UserID: want.UserID}
	if err := SaveToken(renamed); err != nil {
		t.Fatalf("SaveToken after rename: %v", err)
	}
	got, err = LoadToken()
	if err != nil || *got != *renamed {
		t.Fatalf("LoadToken after rename = %#v, %v", got, err)
	}

	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	if _, err := LoadToken(); err == nil {
		t.Fatal("LoadToken succeeded after deletion")
	}
}

func TestTokenStoreSaveErrorPropagated(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	orig := tokenBackend
	tokenBackend = &errorBackend{err: errors.New("disk full")}
	t.Cleanup(func() { tokenBackend = orig })

	err := SaveToken(&StoredToken{AccessToken: "token", Username: "octo", UserID: 123})
	if err == nil {
		t.Fatal("expected error from SaveToken, got nil")
	}
}

func TestTokenStoreReportsLegacyCleanupFailure(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataDir)
	stubBackend(t)

	// Make legacy path a directory so os.Remove fails.
	legacy := filepath.Join(dataDir, "enbu", "token.json")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := SaveToken(&StoredToken{AccessToken: "token", Username: "octo", UserID: 123})
	if err == nil {
		t.Fatal("expected legacy cleanup error, got nil")
	}
	// Token was still saved; LoadToken must succeed.
	if _, err := LoadToken(); err != nil {
		t.Fatalf("credential not retained after legacy cleanup failure: %v", err)
	}
}

func TestGitHubTokenIsEphemeral(t *testing.T) {
	stubBackend(t)
	t.Setenv("GITHUB_TOKEN", "ci-token")
	t.Setenv("GITHUB_ACTOR", "ci-user")
	token, err := LoadToken()
	if err != nil || token.AccessToken != "ci-token" || token.Username != "ci-user" {
		t.Fatalf("LoadToken = %#v, %v", token, err)
	}
	// Env token must NOT be persisted in the backend.
	if _, err := tokenBackend.Load(tokenKeyringService, tokenKeyringAccount); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("GITHUB_TOKEN was persisted in backend")
	}
}

func TestDeleteTokenRemovesLegacyFile(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataDir)
	stubBackend(t)

	legacy := filepath.Join(dataDir, "enbu", "token.json")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}

	_ = DeleteToken()
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy token still exists: %v", err)
	}
}

// errorBackend is a Backend that always returns the given error.
type errorBackend struct{ err error }

func (e *errorBackend) Store(_, _ string, _ []byte) error { return e.err }
func (e *errorBackend) Load(_, _ string) ([]byte, error)  { return nil, e.err }
func (e *errorBackend) Delete(_, _ string) error          { return e.err }

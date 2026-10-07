package auth

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/enbu-net/enbu/pkg/keystore"
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

func TestTokenStoreRoundTrip(t *testing.T) {
	stubBackend(t)

	want := &StoredToken{AccessToken: "token", Username: "octo", UserID: 123}
	if err := SaveToken(want); err != nil {
		t.Fatalf("SaveToken: %v", err)
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

func TestDeleteTokenRemovesStoredToken(t *testing.T) {
	stubBackend(t)
	if err := SaveToken(&StoredToken{AccessToken: "token", Username: "octo", UserID: 123}); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	if _, err := tokenBackend.Load(tokenKeyringService, tokenKeyringAccount); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("token still stored: %v", err)
	}
	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken without a token: %v", err)
	}
}

// errorBackend is a Backend that always returns the given error.
type errorBackend struct{ err error }

func (e *errorBackend) Store(_, _ string, _ []byte) error { return e.err }
func (e *errorBackend) Load(_, _ string) ([]byte, error)  { return nil, e.err }
func (e *errorBackend) Delete(_, _ string) error          { return e.err }

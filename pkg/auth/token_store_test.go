package auth

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/keystore"
)

// memoryBackend is an in-memory OS keyring.
type memoryBackend map[string][]byte

func (m memoryBackend) Store(service, key string, b []byte) error {
	m[service+"/"+key] = append([]byte(nil), b...)
	return nil
}
func (m memoryBackend) Load(service, key string) ([]byte, error) {
	b, ok := m[service+"/"+key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return b, nil
}
func (m memoryBackend) Delete(service, key string) error {
	if _, ok := m[service+"/"+key]; !ok {
		return fs.ErrNotExist
	}
	delete(m, service+"/"+key)
	return nil
}

// stubBackend replaces tokenBackend with an in-memory store for the duration of the test.
func stubBackend(t *testing.T) {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", "")
	orig := tokenBackend
	tokenBackend = memoryBackend{}
	t.Cleanup(func() { tokenBackend = orig })
	useDataDir(t, t.TempDir())
}

// useDataDir makes dir the data directory that records the account in use.
func useDataDir(t *testing.T, dir string) {
	t.Helper()
	orig := activePath
	activePath = func() string { return filepath.Join(dir, "github-account.json") }
	t.Cleanup(func() { activePath = orig })
}

// A locked keyring is reported with its own code on every token operation.
func TestTokenStoreReportsALockedKeyring(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	orig := tokenBackend
	tokenBackend = &errorBackend{err: fmt.Errorf("%w: test", keystore.ErrLocked)}
	t.Cleanup(func() { tokenBackend = orig })
	if _, err := LoadToken(); !apperr.Is(err, apperr.CodeKeyringLocked) {
		t.Fatalf("LoadToken = %v", err)
	}
	if err := SaveToken(&StoredToken{AccessToken: "t", Username: "u", UserID: 1}); !apperr.Is(err, apperr.CodeKeyringLocked) {
		t.Fatalf("SaveToken = %v", err)
	}
	if err := DeleteToken(); !apperr.Is(err, apperr.CodeKeyringLocked) {
		t.Fatalf("DeleteToken = %v", err)
	}
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

func TestSigningInAddsAnAccountAndUsesIt(t *testing.T) {
	stubBackend(t)
	work := &StoredToken{AccessToken: "work-token", Username: "octo-work", UserID: 1}
	home := &StoredToken{AccessToken: "home-token", Username: "octo", UserID: 2}
	for _, token := range []*StoredToken{work, home} {
		if err := SaveToken(token); err != nil {
			t.Fatalf("SaveToken(%s): %v", token.Username, err)
		}
	}
	logins, current, err := Accounts()
	if err != nil || !reflect.DeepEqual(logins, []string{"octo-work", "octo"}) || current != "octo" {
		t.Fatalf("Accounts = %v, %q, %v", logins, current, err)
	}

	if _, err := SwitchAccount("OCTO-WORK"); err != nil {
		t.Fatalf("SwitchAccount: %v", err)
	}
	if got, err := LoadToken(); err != nil || *got != *work {
		t.Fatalf("LoadToken after switch = %#v, %v", got, err)
	}
	if _, err := SwitchAccount("nobody"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("SwitchAccount to an unknown login = %v", err)
	}

	// Signing in again replaces the token, keeps one entry, and uses it.
	again := &StoredToken{AccessToken: "home-token-2", Username: "octo", UserID: 2}
	if err := SaveToken(again); err != nil {
		t.Fatalf("SaveToken again: %v", err)
	}
	if logins, current, _ := Accounts(); !reflect.DeepEqual(logins, []string{"octo-work", "octo"}) || current != "octo" {
		t.Fatalf("Accounts after signing in again = %v, %q", logins, current)
	}
	if got, err := LoadToken(); err != nil || *got != *again {
		t.Fatalf("LoadToken after signing in again = %#v, %v", got, err)
	}
}

func TestSigningOutFallsBackToTheLatestAccount(t *testing.T) {
	stubBackend(t)
	for i, login := range []string{"a", "b", "c"} {
		if err := SaveToken(&StoredToken{AccessToken: "t-" + login, Username: login, UserID: int64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SwitchAccount("a"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAccount("b"); err != nil {
		t.Fatalf("DeleteAccount(b): %v", err)
	}
	if logins, current, _ := Accounts(); !reflect.DeepEqual(logins, []string{"a", "c"}) || current != "a" {
		t.Fatalf("Accounts after signing out of another account = %v, %q", logins, current)
	}
	if err := DeleteToken(); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	if logins, current, _ := Accounts(); !reflect.DeepEqual(logins, []string{"c"}) || current != "c" {
		t.Fatalf("Accounts after signing out of the one in use = %v, %q", logins, current)
	}
	if err := DeleteAccount("a"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("DeleteAccount of an account not signed in = %v", err)
	}
}

// Each data directory chooses its own account from the one keyring, so two
// people can try a workspace on one computer.
func TestEachDataDirectoryChoosesItsAccount(t *testing.T) {
	stubBackend(t)
	first, second := t.TempDir(), t.TempDir()
	useDataDir(t, first)
	if err := SaveToken(&StoredToken{AccessToken: "ta", Username: "alice", UserID: 1}); err != nil {
		t.Fatal(err)
	}
	useDataDir(t, second)
	if err := SaveToken(&StoredToken{AccessToken: "tb", Username: "bob", UserID: 2}); err != nil {
		t.Fatal(err)
	}
	useDataDir(t, first)
	if got, err := LoadToken(); err != nil || got.Username != "alice" {
		t.Fatalf("LoadToken in the first data directory = %#v, %v", got, err)
	}
	useDataDir(t, second)
	if got, err := LoadToken(); err != nil || got.Username != "bob" {
		t.Fatalf("LoadToken in the second data directory = %#v, %v", got, err)
	}

	// A data directory that chose nothing, or holds a damaged choice, uses the latest sign-in.
	third := t.TempDir()
	useDataDir(t, third)
	if err := os.WriteFile(filepath.Join(third, "github-account.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadToken(); err != nil || got.Username != "bob" {
		t.Fatalf("LoadToken with a damaged choice = %#v, %v", got, err)
	}
	if _, err := SwitchAccount("alice"); err != nil {
		t.Fatal(err)
	}
	if err := UseLatestAccount(); err != nil {
		t.Fatalf("UseLatestAccount: %v", err)
	}
	if got, _ := LoadToken(); got.Username != "bob" {
		t.Fatalf("LoadToken after UseLatestAccount = %q, want bob", got.Username)
	}
}

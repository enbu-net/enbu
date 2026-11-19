package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/winbridge"
)

type rejectedTPM struct{ reason error }

func (t rejectedTPM) ProbeECDH() error { return t.reason }
func (rejectedTPM) CreateECDH() ([]byte, identity.TPMObject, identity.HardwareKey, error) {
	panic("unexpected TPM key creation")
}
func (rejectedTPM) LoadECDH([]byte, identity.TPMObject) (identity.HardwareKey, error) {
	panic("unexpected TPM key load")
}

func TestCredentialBackendPolicy(t *testing.T) {
	for _, tt := range []struct {
		name, mode, wantState string
		probe, ring           error
		tpmKnown, ringKnown   bool
	}{
		{name: "missing TPM", probe: fs.ErrNotExist, wantState: "available"},
		{name: "unsupported TPM", probe: identity.ErrTPMUnsupported, wantState: "available"},
		{name: "missing keyring", probe: fs.ErrNotExist, ring: keystore.ErrNoKeyring, wantState: "keyring_missing"},
		{name: "locked keyring", probe: fs.ErrNotExist, ring: keystore.ErrLocked, wantState: "keyring_locked"},
		{name: "permissions", probe: fs.ErrPermission, wantState: "tpm_permission_denied"},
		{name: "transport", probe: errors.New("device I/O failure"), wantState: "unavailable"},
		{name: "missing saved TPM", probe: fs.ErrNotExist, tpmKnown: true, wantState: "tpm_absent"},
		{name: "keyring conflict", mode: "keyring", tpmKnown: true, wantState: "configuration_conflict"},
		{name: "hardware conflict", mode: "hardware", ringKnown: true, wantState: "configuration_conflict"},
		{name: "hardware required", mode: "hardware", probe: fs.ErrNotExist, wantState: "tpm_absent"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "github-auth")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			mode := tt.mode
			if mode == "" {
				mode = "auto"
			}
			s := credentialStores{
				mode: mode, path: filepath.Join(dir, storeFile),
				tpm: rejectedTPM{reason: tt.probe}, ring: keyringStore{backend: memoryBackend{}, dir: dir},
			}
			if tt.ring != nil {
				s.ring.backend = &errorBackend{err: tt.ring}
			}
			if tt.tpmKnown {
				if err := markBackend(dir, tpmSelectionFile); err != nil {
					t.Fatal(err)
				}
			}
			if tt.ringKnown {
				if err := markBackend(dir, keyringSelectionFile); err != nil {
					t.Fatal(err)
				}
			}
			d := s.diagnose()
			if d.State != tt.wantState {
				t.Fatalf("diagnosis = %+v, want state %s", d, tt.wantState)
			}
			if tt.wantState == "available" && d.Backend != "keyring" {
				t.Fatalf("diagnosis = %+v, want keyring", d)
			}
		})
	}
}

func TestCredentialErrorDistinguishesTPMAndStoreFailures(t *testing.T) {
	if !apperr.Is(classifyTPMLoad(fs.ErrPermission), apperr.CodeAuthTPMAccessDenied) {
		t.Fatal("TPM permission error was not classified")
	}
	if err := authStoreError(fs.ErrPermission); apperr.Is(err, apperr.CodeAuthTPMAccessDenied) {
		t.Fatal("filesystem or keyring permission error was classified as TPM access")
	}
	transportErr := errors.New("TPM transport failed")
	if err := classifyTPMLoad(transportErr); !errors.Is(err, transportErr) || errors.Is(err, errCorruptStore) {
		t.Fatal("transport error was classified as corrupted data")
	}
}

func TestEnvironmentTokenIgnoresUnavailableTPM(t *testing.T) {
	stubBackend(t)
	t.Setenv("ENBU_AUTH_BACKEND", "auto")
	t.Setenv("GITHUB_TOKEN", "environment-credential")
	t.Setenv("GITHUB_ACTOR", "environment-user")
	original := systemTPM
	systemTPM = func() tpmKeys { return rejectedTPM{reason: fs.ErrPermission} }
	t.Cleanup(func() { systemTPM = original })
	token, err := LoadToken()
	if err != nil || token.Username != "environment-user" {
		t.Fatalf("environment authentication failed: %v", err)
	}
	if err := SaveToken(testAccount(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(authStoreDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("environment created persistent state: %v", err)
	}
	d := DiagnoseCredentials()
	if !d.Environment || d.State != "tpm_permission_denied" {
		t.Fatalf("diagnosis = %+v", d)
	}
}

func testAccount(id int64) *StoredToken {
	return &StoredToken{
		UserID: id, Username: fmt.Sprintf("account-%d", id),
		AccessToken: fmt.Sprintf("test-sensitive-credential-%d", id),
	}
}

type migrationFixture struct {
	stored    storedAccounts
	saveErr   error
	verifyErr error
	reads     int
}

func (f *migrationFixture) load() (storedAccounts, error) {
	f.reads++
	if f.reads == 2 && f.verifyErr != nil {
		return storedAccounts{}, f.verifyErr
	}
	stored := f.stored
	stored.Accounts = slices.Clone(stored.Accounts)
	return stored, nil
}

func (f *migrationFixture) save(stored storedAccounts) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.stored = stored
	return nil
}

func (f *migrationFixture) reset() error { panic("unexpected reset") }

func (f *migrationFixture) diagnose() CredentialDiagnosis { panic("unexpected diagnosis") }

type failingCleanupRing struct {
	keystore.Backend
	err error
}

func (f *failingCleanupRing) Delete(service, key string) error {
	if f.err != nil {
		return f.err
	}
	return f.Backend.Delete(service, key)
}

func writeLegacy(t *testing.T, ring keyringStore, accounts ...*StoredToken) {
	t.Helper()
	var stored storedAccounts
	for _, account := range accounts {
		stored.Accounts = append(stored.Accounts, *account)
	}
	data, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.backend.Store(tokenKeyringService, tokenKeyringAccount, data); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationKeepsLegacyWhenWriteOrVerificationFails(t *testing.T) {
	injected := errors.New("injected failure")
	for _, fixture := range []*migrationFixture{{saveErr: injected}, {verifyErr: injected}} {
		dir := t.TempDir()
		s := credentialStores{ring: keyringStore{backend: memoryBackend{}, dir: dir}}
		writeLegacy(t, s.ring, testAccount(1))
		if err := s.migrate(fixture); !errors.Is(err, injected) {
			t.Fatalf("migration = %v, want injected failure", err)
		}
		if data, err := s.ring.read(); err != nil || len(data) == 0 {
			t.Fatalf("migration lost legacy data: %v", err)
		}
	}
}

func TestMigrationRecoversAfterCommitWithoutResurrectingAccounts(t *testing.T) {
	stop := errors.New("legacy keyring delete was interrupted")
	ring := &failingCleanupRing{Backend: memoryBackend{}, err: stop}
	s := credentialStores{ring: keyringStore{backend: ring, dir: t.TempDir()}}
	old, current, other := testAccount(1), testAccount(1), testAccount(2)
	current.AccessToken = "newer-tpm-token"
	writeLegacy(t, s.ring, old, other)
	f := &migrationFixture{stored: storedAccounts{Accounts: []StoredToken{*current}}}
	if err := s.migrate(f); !errors.Is(err, stop) {
		t.Fatalf("first migration = %v", err)
	}
	if f.stored.Migration != migrationPending || !slices.Equal(f.stored.Accounts, []StoredToken{*other, *current}) {
		t.Fatal("migration did not keep the TPM account and record pending cleanup")
	}
	// Simulate another command signing out of both accounts after restart.
	restarted := &migrationFixture{stored: f.stored}
	restarted.stored.Accounts = nil
	ring.err = nil
	if err := s.migrate(restarted); err != nil {
		t.Fatal(err)
	}
	if restarted.stored.Migration != migrationComplete || len(restarted.stored.Accounts) != 0 {
		t.Fatal("retry restored signed-out accounts")
	}
	if _, err := s.ring.read(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("legacy token still exists: %v", err)
	}
	writeLegacy(t, s.ring, old) // An older client recreates the entry.
	if err := s.migrate(restarted); err != nil || len(restarted.stored.Accounts) != 0 {
		t.Fatalf("completed migration reopened the legacy entry: %v", err)
	}
}

func TestMigrationRecordsMissingLegacyEntry(t *testing.T) {
	s := credentialStores{ring: keyringStore{backend: memoryBackend{}, dir: t.TempDir()}}
	f := &migrationFixture{}
	if err := s.migrate(f); err != nil {
		t.Fatal(err)
	}
	if f.stored.Migration != migrationComplete || len(f.stored.Accounts) != 0 {
		t.Fatal("migration did not record the empty legacy store")
	}
}

func TestMigrationRefusesChangedLegacyEntry(t *testing.T) {
	ring := &failingCleanupRing{Backend: memoryBackend{}, err: fs.ErrPermission}
	s := credentialStores{ring: keyringStore{backend: ring, dir: t.TempDir()}}
	writeLegacy(t, s.ring, testAccount(1))
	f := &migrationFixture{}
	if err := s.migrate(f); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("migration = %v", err)
	}
	ring.err = nil
	writeLegacy(t, s.ring, testAccount(2))
	if err := s.migrate(f); err == nil || !strings.Contains(err.Error(), "changed after migration") {
		t.Fatalf("migration accepted a changed legacy entry: %v", err)
	}
	if _, err := s.ring.read(); err != nil {
		t.Fatalf("changed entry was removed: %v", err)
	}
}

func pipeAuthBridge(t *testing.T) *winbridge.Client {
	t.Helper()
	client, server := net.Pipe()
	stopped := make(chan error, 1)
	go func() {
		defer func() { _ = server.Close() }()
		s := winbridge.Server{Version: "test", GitHubAuth: ServeGitHubAuth}
		stopped <- s.Serve(t.Context(), server, server)
	}()
	c := &winbridge.Client{Dial: func() (*winbridge.Conn, error) {
		return &winbridge.Conn{R: client, W: client, Close: func() error { _ = client.Close(); return <-stopped }}, nil
	}}
	t.Cleanup(func() { _ = c.Close(); _ = client.Close() })
	return c
}

func TestGitHubCredentialBridgeAccountOperations(t *testing.T) {
	stubBackend(t)
	c := pipeAuthBridge(t)
	for id := int64(1); id <= 2; id++ {
		if err := c.GitHubAuth("save", accountRequest{Token: testAccount(id)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	var d CredentialDiagnosis
	if err := c.GitHubAuth("diagnose", struct{}{}, &d); err != nil || d.Backend != "keyring" || !d.SignedIn {
		t.Fatalf("remote diagnosis = %+v, %v", d, err)
	}
	var result accountResult
	if err := c.GitHubAuth("list", accountRequest{Active: 1}, &result); err != nil || result.Current != "account-1" || result.Token != nil || len(result.Logins) != 2 {
		t.Fatalf("remote accounts incorrect: %v", err)
	}
	if err := c.GitHubAuth("switch", accountRequest{Login: "account-2"}, &result); err != nil ||
		result.Token == nil || *result.Token != *testAccount(2) {
		t.Fatalf("remote switch incorrect: %v", err)
	}
	if err := c.GitHubAuth("delete", accountRequest{Active: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.GitHubAuth("reset", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.GitHubAuth("load", accountRequest{}, nil); !apperr.Is(err, apperr.CodeNotAuthenticated) {
		t.Fatalf("remote load after reset = %v", err)
	}
	if err := c.GitHubAuth("save", map[string]string{"path": "arbitrary"}, nil); err == nil {
		t.Fatal("the bridge accepted a filesystem path")
	}
	if err := c.GitHubAuth("keyring.load", map[string]string{"service": "enbu"}, nil); err == nil {
		t.Fatal("the bridge accepted a keyring entry")
	}
}

func TestExplicitResetToKeyringDiscardsLegacyAndTPMBinding(t *testing.T) {
	stubBackend(t)
	dir := authStoreDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := markBackend(dir, tpmSelectionFile); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, storeFile)
	if err := os.WriteFile(path, []byte("unreadable TPM data"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeLegacy(t, localStores().ring, testAccount(1))
	if _, err := LoadToken(); !apperr.Is(err, apperr.CodeAuthBackendConflict) {
		t.Fatalf("explicit mode did not reject the saved TPM binding: %v", err)
	}
	if err := ResetCredentials(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(); !apperr.Is(err, apperr.CodeNotAuthenticated) {
		t.Fatalf("reset reopened legacy credentials: %v", err)
	}
	if err := SaveToken(testAccount(2)); err != nil {
		t.Fatalf("sign in after choosing keyring: %v", err)
	}
}

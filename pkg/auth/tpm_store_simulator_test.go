//go:build linux && cgo

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
)

type simulatorConn struct {
	inner transport.TPM
	mu    sync.Mutex
}

func (c *simulatorConn) Send(command []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inner.Send(command)
}
func (*simulatorConn) Close() error { return nil }

type forbiddenKeyring struct{}

func (forbiddenKeyring) Load(string, string) ([]byte, error) { panic("called legacy keyring") }
func (forbiddenKeyring) Store(string, string, []byte) error  { panic("called legacy keyring") }
func (forbiddenKeyring) Delete(string, string) error         { panic("called legacy keyring") }

func useSimulatorTPM(t *testing.T) *simulator.Simulator {
	t.Helper()
	sim, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	conn := &simulatorConn{inner: transport.FromReadWriter(sim)}
	orig := systemTPM
	systemTPM = func() tpmKeys {
		return &identity.TPMBackend{Device: "reference simulator", Open: func() (transport.TPMCloser, error) {
			return conn, nil
		}}
	}
	t.Cleanup(func() { systemTPM = orig })
	return sim
}

func TestTPMCredentialsLifecycleAndIntegrity(t *testing.T) {
	stubBackend(t)
	t.Setenv("ENBU_AUTH_BACKEND", "auto")
	sim := useSimulatorTPM(t)
	tokenBackend = forbiddenKeyring{}
	dir := authStoreDir()
	path := filepath.Join(dir, storeFile)
	if d := DiagnoseCredentials(); d.Backend != "tpm" || d.State != "available" || d.SignedIn {
		t.Fatalf("initial diagnosis = %+v", d)
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("diagnosis created credential state: %v", err)
	}
	first := testAccount(1)
	if err := SaveToken(first); err != nil {
		t.Fatal(err)
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadToken(); err != nil || *got != *first {
		t.Fatalf("TPM reload after restart failed: %v", err)
	}
	useDataDir(t, t.TempDir())
	if err := SaveToken(testAccount(2)); err != nil {
		t.Fatal(err)
	}
	if logins, current, err := Accounts(); err != nil || !slices.Equal(logins, []string{"account-1", "account-2"}) || current != "account-2" {
		t.Fatalf("accounts = %v, %q, %v", logins, current, err)
	}
	useDataDir(t, t.TempDir())
	if _, err := SwitchAccount("ACCOUNT-1"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(first.AccessToken)) || bytes.Contains(data, []byte(first.Username)) {
		t.Fatal("TPM file contains plaintext account data")
	}
	for _, tt := range []struct {
		name   string
		change func(*tokenEnvelope)
	}{
		{"ciphertext", func(e *tokenEnvelope) { e.Sealed[len(e.Sealed)-1] ^= 1 }},
		{"key blob", func(e *tokenEnvelope) { e.Metadata.Key.Private[len(e.Metadata.Key.Private)-1] ^= 1 }},
		{"object name", func(e *tokenEnvelope) { e.Metadata.Key.Name[0] ^= 1 }},
		{"version", func(e *tokenEnvelope) { e.Metadata.Version++ }},
		{"purpose", func(e *tokenEnvelope) { e.Metadata.Purpose = "wrong" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var e tokenEnvelope
			if err := json.Unmarshal(data, &e); err != nil {
				t.Fatal(err)
			}
			tt.change(&e)
			changed, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadToken(); !errors.Is(err, errCorruptStore) {
				t.Fatalf("tampered credential load = %v", err)
			}
			if err := SaveToken(testAccount(3)); !errors.Is(err, errCorruptStore) {
				t.Fatalf("write replaced a damaged TPM store: %v", err)
			}
		})
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sim.ManufactureReset(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(); !errors.Is(err, identity.ErrTPMParentChanged) {
		t.Fatalf("credential load from cleared TPM = %v", err)
	}
	if d := DiagnoseCredentials(); d.State != "tpm_changed" {
		t.Fatalf("diagnosis after clear = %+v", d)
	}
	if err := ResetCredentials(); err != nil {
		t.Fatal(err)
	}
	if err := SaveToken(first); err != nil {
		t.Fatal(err)
	}
	if err := DeleteAccount(""); err != nil {
		t.Fatal(err)
	}
	if d := DiagnoseCredentials(); d.State != "available" || d.SignedIn || d.Migration != migrationComplete {
		t.Fatalf("empty store diagnosis = %+v", d)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(); !errors.Is(err, errCorruptStore) {
		t.Fatalf("missing file did not retain the TPM binding: %v", err)
	}
}

func TestTPMCredentialsMigrationThroughBridge(t *testing.T) {
	stubBackend(t)
	t.Setenv("ENBU_AUTH_BACKEND", "auto")
	useSimulatorTPM(t)
	t.Setenv("GITHUB_TOKEN", "external-token")
	writeLegacy(t, localStores().ring, testAccount(1))
	c := pipeAuthBridge(t)
	if err := c.GitHubAuth("migrate", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	tokenBackend = forbiddenKeyring{}
	var result accountResult
	if err := c.GitHubAuth("load", accountRequest{}, &result); err != nil ||
		result.Token == nil || *result.Token != *testAccount(1) {
		t.Fatalf("remote migrated account incorrect: %v", err)
	}
	var d CredentialDiagnosis
	if err := c.GitHubAuth("diagnose", struct{}{}, &d); err != nil || d.Backend != "tpm" || d.Migration != migrationComplete {
		t.Fatalf("remote TPM diagnosis = %+v, %v", d, err)
	}
	if err := c.GitHubAuth("delete", accountRequest{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.GitHubAuth("load", accountRequest{}, nil); !apperr.Is(err, apperr.CodeNotAuthenticated) {
		t.Fatalf("empty remote TPM store = %v", err)
	}
	if got, err := LoadToken(); err != nil || got.AccessToken != "external-token" {
		t.Fatalf("local environment token was unavailable: %v", err)
	}
}

func TestTPMCredentialsConcurrentAccounts(t *testing.T) {
	stubBackend(t)
	t.Setenv("ENBU_AUTH_BACKEND", "auto")
	useSimulatorTPM(t)
	tokenBackend = forbiddenKeyring{}
	if err := SaveToken(testAccount(1)); err != nil {
		t.Fatal(err)
	}
	operations := []func() error{
		func() error { return SaveToken(testAccount(2)) },
		func() error { return SaveToken(testAccount(3)) },
		func() error { return DeleteAccount("account-1") },
	}
	var group sync.WaitGroup
	for _, op := range operations {
		group.Go(func() {
			if err := op(); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	logins, _, err := Accounts()
	slices.Sort(logins)
	if err != nil || !slices.Equal(logins, []string{"account-2", "account-3"}) {
		t.Fatalf("concurrent credential updates = %v, %v", logins, err)
	}
}

func TestTPMCredentialsRejectSymlink(t *testing.T) {
	stubBackend(t)
	t.Setenv("ENBU_AUTH_BACKEND", "auto")
	useSimulatorTPM(t)
	dir := authStoreDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, storeFile)); err != nil {
		t.Fatal(err)
	}
	for _, op := range []func() error{func() error { return SaveToken(testAccount(1)) }, ResetCredentials} {
		if err := op(); err == nil {
			t.Fatal("operation followed a symbolic link")
		}
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "keep" {
		t.Fatalf("symlink target changed: %v", err)
	}
	if d := DiagnoseCredentials(); d.State == "available" {
		t.Fatal("diagnosis accepted a symbolic link")
	}
}

// This child exits just as the legacy entry would be deleted, after verifying
// the new TPM data. A fresh process must be able to finish cleanup.
func TestTPMMigrationInterruptedProcess(t *testing.T) {
	dir := os.Getenv("ENBU_TEST_AUTH_MIGRATION_CHILD")
	if dir == "" {
		return
	}
	ring := &exitBeforeDelete{Backend: memoryBackend{}}
	s := fixedSeedMigrationStores(t, dir, ring)
	writeLegacy(t, s.ring, testAccount(1))
	if err := s.maintain("migrate"); err != nil {
		t.Fatal(err)
	}
	t.Fatal("migration did not reach legacy cleanup")
}

type exitBeforeDelete struct{ keystore.Backend }

func (*exitBeforeDelete) Delete(string, string) error {
	os.Exit(23)
	return nil
}

func fixedSeedMigrationStores(t *testing.T, dir string, ring keystore.Backend) credentialStores {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(42)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	conn := &simulatorConn{inner: transport.FromReadWriter(sim)}
	return credentialStores{
		mode: "auto", path: filepath.Join(dir, storeFile), ring: keyringStore{backend: ring, dir: dir},
		tpm: &identity.TPMBackend{Open: func() (transport.TPMCloser, error) { return conn, nil }},
	}
}

func TestTPMMigrationResumesAfterProcessExit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "github-auth")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTPMMigrationInterruptedProcess$")
	cmd.Env = append(os.Environ(), "ENBU_TEST_AUTH_MIGRATION_CHILD="+dir)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("migration subprocess = %v: %s", err, output)
	}
	s := fixedSeedMigrationStores(t, dir, memoryBackend{})
	writeLegacy(t, s.ring, testAccount(1))
	if d := s.diagnose(); d.Migration != migrationPending || !d.SignedIn {
		t.Fatalf("diagnosis after interruption = %+v", d)
	}
	if err := s.maintain("migrate"); err != nil {
		t.Fatal(err)
	}
	if d := s.diagnose(); d.Migration != migrationComplete || !d.SignedIn {
		t.Fatalf("diagnosis after resume = %+v", d)
	}
	if _, err := s.ring.read(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("legacy data remains after resume: %v", err)
	}
}

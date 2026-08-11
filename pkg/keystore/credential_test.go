package keystore

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
)

type credentialBackend struct {
	protection  artifact.CredentialProtection
	service     string
	key         string
	value       []byte
	storeCalls  int
	loadCalls   int
	deleteCalls int
}

func (backend *credentialBackend) Protection() artifact.CredentialProtection {
	return backend.protection
}

func (backend *credentialBackend) Store(service, key string, value []byte) error {
	backend.storeCalls++
	backend.service = service
	backend.key = key
	backend.value = append([]byte(nil), value...)
	return nil
}

func (backend *credentialBackend) Load(service, key string) ([]byte, error) {
	backend.loadCalls++
	backend.service = service
	backend.key = key
	if backend.value == nil {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), backend.value...), nil
}

func (backend *credentialBackend) Delete(service, key string) error {
	backend.deleteCalls++
	backend.service = service
	backend.key = key
	backend.value = nil
	return nil
}

func TestCredentialStoreRoundTripUsesFixedService(t *testing.T) {
	backend := &credentialBackend{protection: artifact.CredentialProtectionOS}
	store, err := NewCredentialStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("private-device-credential")
	if err := store.Store(context.Background(), "device-identity-v1", input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	if backend.service != artifactCredentialService || backend.key != "device-identity-v1" {
		t.Fatalf("backend target = %q/%q", backend.service, backend.key)
	}
	loaded, err := store.Load(context.Background(), "device-identity-v1")
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != "private-device-credential" {
		t.Fatalf("loaded = %q", loaded)
	}
	loaded[0] = 'Y'
	if string(backend.value) != "private-device-credential" {
		t.Fatal("Load returned the backend's mutable buffer")
	}
	if err := store.Delete(context.Background(), "device-identity-v1"); err != nil {
		t.Fatal(err)
	}
	if backend.storeCalls != 1 || backend.loadCalls != 1 || backend.deleteCalls != 1 {
		t.Fatalf("backend calls = store:%d load:%d delete:%d", backend.storeCalls, backend.loadCalls, backend.deleteCalls)
	}
}

func TestCredentialStorePersistsArtifactDeviceIdentity(t *testing.T) {
	backend := &credentialBackend{protection: artifact.CredentialProtectionOS}
	store, err := NewCredentialStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := artifact.SaveDeviceIdentity(context.Background(), store, identity); err != nil {
		t.Fatal(err)
	}
	loaded, err := artifact.LoadDeviceIdentity(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceID() != identity.DeviceID() || loaded.RecipientString() != identity.RecipientString() {
		t.Fatal("loaded device identity does not match the stored identity")
	}
	if backend.service != artifactCredentialService || backend.key != "device-identity-v1" {
		t.Fatalf("backend target = %q/%q", backend.service, backend.key)
	}
}

func TestCredentialStoreRejectsUnprotectedBackends(t *testing.T) {
	var nilKeyring *KeyringBackend
	for name, backend := range map[string]Backend{
		"nil":           nil,
		"typed nil":     nilKeyring,
		"plaintext":     &TextBackend{},
		"unavailable":   &UnavailableBackend{},
		"misclassified": &credentialBackend{protection: "plaintext"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCredentialStore(backend); !errors.Is(err, artifact.ErrInsecureCredentialStore) {
				t.Fatalf("NewCredentialStore() error = %v", err)
			}
		})
	}
}

func TestCredentialStoreHonorsCanceledContextBeforeBackendCall(t *testing.T) {
	backend := &credentialBackend{protection: artifact.CredentialProtectionOS}
	store, err := NewCredentialStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Store(ctx, "device-identity-v1", []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Store() error = %v", err)
	}
	if _, err := store.Load(ctx, "device-identity-v1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Load() error = %v", err)
	}
	if err := store.Delete(ctx, "device-identity-v1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete() error = %v", err)
	}
	if backend.storeCalls != 0 || backend.loadCalls != 0 || backend.deleteCalls != 0 {
		t.Fatal("canceled calls reached the backend")
	}
}

func TestCredentialStoreFailsClosedIfBackendProtectionChanges(t *testing.T) {
	backend := &credentialBackend{protection: artifact.CredentialProtectionOS}
	store, err := NewCredentialStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	backend.protection = "plaintext"
	if got := store.Protection(); got == artifact.CredentialProtectionOS {
		t.Fatalf("Protection() = %q after backend downgrade", got)
	}
	if err := store.Store(context.Background(), "device-identity-v1", []byte("secret")); !errors.Is(err, artifact.ErrInsecureCredentialStore) {
		t.Fatalf("Store() error = %v", err)
	}
	if backend.storeCalls != 0 {
		t.Fatal("downgraded backend received a credential")
	}
}

func TestKeyringBackendClassifiesAsOSProtected(t *testing.T) {
	if got := (&KeyringBackend{}).Protection(); got != artifact.CredentialProtectionOS {
		t.Fatalf("Protection() = %q", got)
	}
}

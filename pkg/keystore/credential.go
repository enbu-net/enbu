package keystore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/enbu-net/enbu/pkg/artifact"
)

const artifactCredentialService = "enbu.net.artifact-platform.v1"

type protectedBackend interface {
	Backend
	Protection() artifact.CredentialProtection
}

// CredentialStore adapts an OS-protected keystore Backend to the artifact
// device credential contract. The service namespace is fixed so untrusted
// workspace data cannot redirect private device keys to another application.
type CredentialStore struct {
	backend protectedBackend
}

var _ artifact.CredentialStore = (*CredentialStore)(nil)

// NewCredentialStore rejects plaintext, unavailable, unclassified, and nil
// backends. Callers that want the native production backend should pass the
// result of New; there is deliberately no fallback if the OS keyring is absent.
func NewCredentialStore(backend Backend) (*CredentialStore, error) {
	if isNilBackend(backend) {
		return nil, artifact.ErrInsecureCredentialStore
	}
	protected, ok := backend.(protectedBackend)
	if !ok || protected.Protection() != artifact.CredentialProtectionOS {
		return nil, artifact.ErrInsecureCredentialStore
	}
	return &CredentialStore{backend: protected}, nil
}

func (store *CredentialStore) Protection() artifact.CredentialProtection {
	if store == nil || store.backend == nil {
		return ""
	}
	return store.backend.Protection()
}

func (store *CredentialStore) Store(ctx context.Context, key string, value []byte) error {
	if err := store.validate(ctx, key); err != nil {
		return err
	}
	valueCopy := append([]byte(nil), value...)
	defer clearCredential(valueCopy)
	if err := store.backend.Store(artifactCredentialService, key, valueCopy); err != nil {
		return fmt.Errorf("keystore: store artifact credential: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (store *CredentialStore) Load(ctx context.Context, key string) ([]byte, error) {
	if err := store.validate(ctx, key); err != nil {
		return nil, err
	}
	value, err := store.backend.Load(artifactCredentialService, key)
	if err != nil {
		return nil, fmt.Errorf("keystore: load artifact credential: %w", err)
	}
	if err := ctx.Err(); err != nil {
		clearCredential(value)
		return nil, err
	}
	result := append([]byte(nil), value...)
	clearCredential(value)
	return result, nil
}

func (store *CredentialStore) Delete(ctx context.Context, key string) error {
	if err := store.validate(ctx, key); err != nil {
		return err
	}
	if err := store.backend.Delete(artifactCredentialService, key); err != nil {
		return fmt.Errorf("keystore: delete artifact credential: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (store *CredentialStore) validate(ctx context.Context, key string) error {
	if store == nil || store.backend == nil {
		return artifact.ErrInsecureCredentialStore
	}
	if store.backend.Protection() != artifact.CredentialProtectionOS {
		return artifact.ErrInsecureCredentialStore
	}
	if ctx == nil {
		return errors.New("keystore: nil credential context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == "" || len(key) > 253 || strings.IndexByte(key, 0) >= 0 {
		return errors.New("keystore: invalid credential key")
	}
	return nil
}

func isNilBackend(backend Backend) bool {
	if backend == nil {
		return true
	}
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func clearCredential(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

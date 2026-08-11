package keystore

import (
	"fmt"
	"os"

	"github.com/enbu-net/enbu/pkg/artifact"
)

type Backend interface {
	Store(service, key string, secret []byte) error
	Load(service, key string) ([]byte, error)
	Delete(service, key string) error
}

// UnavailableBackend is a fail-closed placeholder used when no OS-protected
// credential store is available. It never writes a plaintext fallback.
type UnavailableBackend struct{ Err error }

func (backend *UnavailableBackend) Store(string, string, []byte) error  { return backend.err() }
func (backend *UnavailableBackend) Load(string, string) ([]byte, error) { return nil, backend.err() }
func (backend *UnavailableBackend) Delete(string, string) error         { return backend.err() }
func (backend *UnavailableBackend) err() error {
	if backend != nil && backend.Err != nil {
		return backend.Err
	}
	return artifact.ErrInsecureCredentialStore
}

func New() (Backend, error) {
	backendType := os.Getenv("ENBU_BACKEND")
	if backendType == "" {
		backendType = "keyring"
	}

	switch backendType {
	case "keyring":
		kb := &KeyringBackend{}
		if err := kb.probe(); err != nil {
			return nil, fmt.Errorf("keystore unavailable: %w", err)
		}
		return kb, nil
	case "text":
		return nil, fmt.Errorf("%w: plaintext backend is disabled", artifact.ErrInsecureCredentialStore)
	default:
		return nil, fmt.Errorf("unknown backend type: %s (supported: keyring, text)", backendType)
	}
}

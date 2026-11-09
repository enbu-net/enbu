package keystore

import (
	"fmt"
	"os"
)

type Backend interface {
	Store(service, key string, secret []byte) error
	Load(service, key string) ([]byte, error)
	Delete(service, key string) error
}

// New returns the backend for the GitHub token: the OS keyring, or a file
// when ENBU_BACKEND=text says so. It never falls back to a file on its own;
// a keyring that is missing or locked fails each operation instead.
func New() (Backend, error) {
	switch backendType := os.Getenv("ENBU_BACKEND"); backendType {
	case "", "keyring":
		return &KeyringBackend{}, nil
	case "text":
		return &TextBackend{}, nil
	default:
		return nil, fmt.Errorf("unknown backend type: %s (supported: keyring, text)", backendType)
	}
}

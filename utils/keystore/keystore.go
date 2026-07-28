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

func New() (Backend, error) {
	backendType := os.Getenv("ENBU_BACKEND")
	if backendType == "" {
		backendType = "keyring"
	}

	switch backendType {
	case "keyring":
		kb := &KeyringBackend{}
		if err := kb.probe(); err != nil {
			return &TextBackend{}, nil
		}
		return kb, nil
	case "text":
		return &TextBackend{}, nil
	default:
		return nil, fmt.Errorf("unknown backend type: %s (supported: keyring, text)", backendType)
	}
}

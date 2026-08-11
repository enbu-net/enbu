package keystore

import (
	"errors"
	"io/fs"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/zalando/go-keyring"
)

type KeyringBackend struct{}

// Protection reports the security property required by the artifact device
// credential contract. KeyringBackend never falls back to a plaintext file.
func (*KeyringBackend) Protection() artifact.CredentialProtection {
	return artifact.CredentialProtectionOS
}

func (k *KeyringBackend) probe() error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		_, err := keyring.Get("enbu-probe", "probe")
		if errors.Is(err, keyring.ErrNotFound) {
			err = nil
		}
		ch <- result{err}
	}()
	select {
	case r := <-ch:
		return r.err
	case <-time.After(3 * time.Second):
		return errors.New("keyring unavailable: timed out")
	}
}

func (k *KeyringBackend) Store(service, key string, secret []byte) error {
	return keyring.Set(service, key, string(secret))
}

func (k *KeyringBackend) Load(service, key string) ([]byte, error) {
	s, err := keyring.Get(service, key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	return []byte(s), nil
}

func (k *KeyringBackend) Delete(service, key string) error {
	err := keyring.Delete(service, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return fs.ErrNotExist
	}
	return err
}

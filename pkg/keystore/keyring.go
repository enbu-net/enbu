package keystore

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/zalando/go-keyring"
)

var (
	// ErrLocked reports an OS keyring that exists but is locked. Reading or
	// writing it would wait for an unlock prompt, which never comes without a
	// desktop session, so enbu asks the person to unlock it instead.
	ErrLocked = errors.New("OS keyring is locked")
	// ErrNoKeyring reports a device without a usable OS keyring: no Secret
	// Service on Linux, or no default collection to keep keys in.
	ErrNoKeyring = errors.New("no OS keyring")
)

// probeTimeout bounds every check of the OS keyring. The checks are D-Bus
// property reads on Linux, and a lookup of a missing entry elsewhere.
const probeTimeout = 3 * time.Second

type KeyringBackend struct{ Clock clock.Clock }

// Probe checks that the OS keyring can store and load keys now, without
// writing a key and without waiting for an unlock prompt.
func (k *KeyringBackend) Probe(ctx context.Context) error {
	c := k.Clock
	if c == nil {
		c = clock.New()
	}
	ctx, cancel := clock.WithTimeout(ctx, c, probeTimeout)
	defer cancel()
	return probeKeyring(ctx)
}

func (k *KeyringBackend) Store(service, key string, secret []byte) error {
	if err := k.ready(); err != nil {
		return err
	}
	return keyring.Set(service, key, string(secret))
}

func (k *KeyringBackend) Load(service, key string) ([]byte, error) {
	if err := k.ready(); err != nil {
		return nil, err
	}
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
	if err := k.ready(); err != nil {
		return err
	}
	err := keyring.Delete(service, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return fs.ErrNotExist
	}
	return err
}

// ready refuses an operation that would block: go-keyring asks the Secret
// Service to unlock a locked collection and then waits for the prompt with no
// timeout. Only Linux needs the check.
func (k *KeyringBackend) ready() error {
	if !checkBeforeUse {
		return nil
	}
	return k.Probe(context.Background())
}

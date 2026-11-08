package keystore

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/zalando/go-keyring"
)

type KeyringBackend struct{ Clock clock.Clock }

// Probe checks access without writing a key or waiting indefinitely for a
// locked or missing Secret Service.
func (k *KeyringBackend) Probe(context.Context) error { return k.probe() }

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
	c := k.Clock
	if c == nil {
		c = clock.New()
	}
	timer := c.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.err
	case <-timer.Chan():
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

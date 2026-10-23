//go:build scenario

package cli

import (
	"io/fs"
	"sync"

	"github.com/enbu-net/enbu/app/apptest"
)

type mockKeyStore struct {
	apptest.Signers
	mu   sync.RWMutex
	data map[string][]byte
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{data: make(map[string][]byte)}
}

func (m *mockKeyStore) storeSecret(_, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), value...)
	return nil
}

func (m *mockKeyStore) loadSecret(_, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), d...), nil
}

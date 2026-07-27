//go:build scenario

package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/enbu-net/enbu/provider"
	"github.com/enbu-net/enbu/utils/keystore"
	"github.com/enbu-net/enbu/utils/oci"
)

type mockRegistry struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMockRegistry() *mockRegistry {
	return &mockRegistry{data: make(map[string][]byte)}
}

func (m *mockRegistry) Push(_ context.Context, ref string, _ string, data []byte, _ string, _ *oci.PushOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[ref] = append([]byte(nil), data...)
	return nil
}

func (m *mockRegistry) Pull(_ context.Context, ref string, _ string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[ref]
	if !ok {
		return nil, fmt.Errorf("%w: %s", oci.ErrNotFound, ref)
	}
	return append([]byte(nil), d...), nil
}

func (m *mockRegistry) ListTags(_ context.Context, ref string, _ string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := ref + ":"
	var tags []string
	for k := range m.data {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			tags = append(tags, k[len(prefix):])
		}
	}
	return tags, nil
}

func (m *mockRegistry) GetDigest(_ context.Context, ref string, _ string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[ref]
	if !ok {
		return "", fmt.Errorf("%w: %s", oci.ErrNotFound, ref)
	}
	sum := sha256.Sum256(d)
	return fmt.Sprintf("sha256:%x", sum), nil
}

type mockTokenProvider struct {
	accessToken string
	username    string
}

func (m *mockTokenProvider) LoadToken() (string, string, error) {
	return m.accessToken, m.username, nil
}

type mockRepoDetector struct {
	owner string
	repo  string
}

func (m *mockRepoDetector) LoadRepo() (string, string, error) {
	return m.owner, m.repo, nil
}

type mockKeyStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{data: make(map[string][]byte)}
}

func (m *mockKeyStore) Store(_, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), value...)
	return nil
}

func (m *mockKeyStore) Load(_, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[key]
	if !ok {
		return nil, keystore.ErrNotFound
	}
	return append([]byte(nil), d...), nil
}

type mockGitHubClient struct {
	user *provider.User
	orgs map[string]bool
}

func (m *mockGitHubClient) GetUser(_ context.Context) (*provider.User, error) {
	return m.user, nil
}

func (m *mockGitHubClient) IsOrganization(_ context.Context, login string) bool {
	return m.orgs[login]
}

func (m *mockGitHubClient) SourceRepoURL(owner, repo string) string {
	return "https://github.com/" + owner + "/" + repo
}

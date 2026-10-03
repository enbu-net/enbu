package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
)

const testWorkspaceID = "11111111-1111-4111-8111-111111111111"

type memRegistry struct {
	mu    sync.RWMutex
	data  map[string][]byte
	media map[string]string
}

func newMemRegistry() *memRegistry {
	return &memRegistry{data: map[string][]byte{}, media: map[string]string{}}
}
func (r *memRegistry) Capabilities() storage.Capabilities {
	return storage.Capabilities{AtomicUpdates: true}
}
func (r *memRegistry) Get(_ context.Context, key string) (storage.Object, storage.Version, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.data[key]
	if !ok {
		return storage.Object{}, "", storage.ErrNotFound
	}
	return storage.Object{MediaType: r.media[key], Data: append([]byte(nil), d...)}, storage.Version(fmt.Sprintf("sha256:%x", sha256.Sum256(d))), nil
}
func (r *memRegistry) Put(_ context.Context, key string, o storage.Object, v storage.Version) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var current storage.Version
	if d, ok := r.data[key]; ok {
		current = storage.Version(fmt.Sprintf("sha256:%x", sha256.Sum256(d)))
	}
	if current != v {
		return storage.ErrConflict
	}
	r.data[key] = append([]byte(nil), o.Data...)
	r.media[key] = o.MediaType
	return nil
}
func (r *memRegistry) List(_ context.Context, prefix string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var keys []string
	for key := range r.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

type conflictOnceRegistry struct {
	storage.Storage
	pushes int
}

func (r *conflictOnceRegistry) Put(ctx context.Context, key string, o storage.Object, v storage.Version) error {
	if key == "enbu-workspace" {
		return r.Storage.Put(ctx, key, o, v)
	}
	r.pushes++
	if r.pushes == 1 {
		return storage.ErrConflict
	}
	return r.Storage.Put(ctx, key, o, v)
}

type staticTokenProvider struct{ token, username string }

func (s *staticTokenProvider) LoadToken() (string, string, error) { return s.token, s.username, nil }

type staticRepoDetector struct{ owner, repo string }

func (s *staticRepoDetector) LoadRepo() (string, string, error) { return s.owner, s.repo, nil }

type memKeyStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMemKeyStore() *memKeyStore { return &memKeyStore{data: make(map[string][]byte)} }

func (m *memKeyStore) storeSecret(_, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), value...)
	return nil
}

func (m *memKeyStore) loadSecret(_, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), d...), nil
}

// newTestApp builds an App wired with in-memory doubles.
// It registers kp as both the recipient and the stored private key,
// and pushes a single secret under the given env if secrets != nil.
func newTestApp(t *testing.T, owner, repo, env string, kp *age.KeyPair, secrets map[string]string) *App {
	t.Helper()
	reg := newMemRegistry()
	ks := newMemKeyStore()

	// store private key
	if err := ks.storeSecret(KeystoreService, testWorkspaceID, []byte(kp.Identity.String())); err != nil {
		t.Fatalf("store private key: %v", err)
	}

	a := &App{
		Storage:       reg,
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector:  &staticRepoDetector{owner: owner, repo: repo},
		Identities:    ks,
	}

	prepareApp(t, a, env)
	if err := reg.Put(context.Background(), RecipientKey(kp.PublicKey), storage.Object{MediaType: recipientMediaType, Data: []byte(kp.PublicKey)}, ""); err != nil {
		t.Fatal(err)
	}

	// pre-populate secrets if provided
	for k, v := range secrets {
		if err := a.AddSecret(context.Background(), env, k, v); err != nil {
			t.Fatalf("AddSecret %s: %v", k, err)
		}
	}

	return a
}

func mustKeyPair(t *testing.T) *age.KeyPair {
	t.Helper()
	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return kp
}

func TestSyncSecretsRetriesStructuredConflict(t *testing.T) {
	a := newTestApp(t, "acme", "repo", "dev", mustKeyPair(t), map[string]string{"KEY": "value"})
	registry := &conflictOnceRegistry{Storage: a.Storage}
	a.Storage = registry

	if err := a.SyncSecrets(context.Background(), "dev"); err != nil {
		t.Fatalf("SyncSecrets: %v", err)
	}
	if registry.pushes != 2 {
		t.Fatalf("pushes = %d, want 2", registry.pushes)
	}
}

// --- tests ---

func TestListSecrets_ReturnsStoredSecrets(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "bar", "BAZ": "qux"})

	secrets, err := a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if secrets["FOO"] != "bar" || secrets["BAZ"] != "qux" {
		t.Fatalf("unexpected secrets: %v", secrets)
	}
}

func TestListSecrets_ReturnsEmptyMapWhenNoSecrets(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)

	secrets, err := a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected empty map, got: %v", secrets)
	}
}

func TestPullSecrets_ReturnsDotEnvBytes(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "value"})

	dotenv, _, count, err := a.PullSecrets(context.Background(), "default")
	if err != nil {
		t.Fatalf("PullSecrets: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count=1, got %d", count)
	}
	if !strings.Contains(string(dotenv), `KEY="value"`) {
		t.Fatalf("unexpected dotenv: %s", dotenv)
	}
}

func TestPullSecrets_ErrorWhenWrongKey(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "value"})

	// replace stored key with a different identity (cannot decrypt)
	other := mustKeyPair(t)
	ks := newMemKeyStore()
	if err := ks.storeSecret(KeystoreService, testWorkspaceID, []byte(other.Identity.String())); err != nil {
		t.Fatal(err)
	}
	a.Identities = ks

	_, _, _, err := a.PullSecrets(context.Background(), "default")
	if err == nil {
		t.Fatal("expected decryption error with wrong key")
	}
}

func prepareApp(t *testing.T, a *App, env string) {
	t.Helper()
	if a.RepositoryDir == "" {
		a.RepositoryDir = t.TempDir()
	}
	cfg := config.NewProjectWithEnvironment(env)
	cfg.WorkspaceID = testWorkspaceID
	cfg.Storage.URL = "local:///unused"
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.Storage.Put(context.Background(), workspaceKey, storage.Object{MediaType: workspaceMediaType, Data: []byte(testWorkspaceID)}, ""); err != nil {
		t.Fatal(err)
	}
}

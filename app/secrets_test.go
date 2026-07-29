package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/oci"
)

// --- minimal test doubles ---

type memRegistry struct {
	mu   sync.RWMutex
	data map[string][]byte
}

type conflictOnceRegistry struct {
	Registry
	pushes int
}

func (r *conflictOnceRegistry) Push(ctx context.Context, ref, mediaType string, data []byte, token string, opts *oci.PushOptions) error {
	r.pushes++
	if r.pushes == 1 {
		return apperr.New(apperr.CodeConflict, "digest mismatch", nil)
	}
	return r.Registry.Push(ctx, ref, mediaType, data, token, opts)
}

func newMemRegistry() *memRegistry { return &memRegistry{data: make(map[string][]byte)} }

func (r *memRegistry) Push(_ context.Context, ref, _ string, data []byte, _ string, _ *oci.PushOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[ref] = append([]byte(nil), data...)
	return nil
}

func (r *memRegistry) Pull(_ context.Context, ref, _ string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.data[ref]
	if !ok {
		return nil, apperr.New(apperr.CodeArtifactNotFound, fmt.Sprintf("artifact %s not found", ref), nil)
	}
	return append([]byte(nil), d...), nil
}

func (r *memRegistry) ListTags(_ context.Context, ref, _ string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	prefix := ref + ":"
	var tags []string
	for k := range r.data {
		if strings.HasPrefix(k, prefix) {
			tags = append(tags, strings.TrimPrefix(k, prefix))
		}
	}
	return tags, nil
}

func (r *memRegistry) GetDigest(_ context.Context, ref, _ string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.data[ref]
	if !ok {
		return "", apperr.New(apperr.CodeArtifactNotFound, fmt.Sprintf("artifact %s not found", ref), nil)
	}
	sum := sha256.Sum256(d)
	return fmt.Sprintf("sha256:%x", sum), nil
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

func (m *memKeyStore) Store(_, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), value...)
	return nil
}

func (m *memKeyStore) Load(_, key string) ([]byte, error) {
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
	if err := ks.Store(KeystoreService, RepoKeystoreKey(owner, repo), []byte(kp.Identity.String())); err != nil {
		t.Fatalf("store private key: %v", err)
	}

	a := &App{
		Registry:      reg,
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector:  &staticRepoDetector{owner: owner, repo: repo},
		KeyStore:      ks,
	}

	// register recipient
	registryRef := a.registryRef(owner, repo)
	recipientRef := fmt.Sprintf("%s:%salice", registryRef, RecipientTagPrefix())
	if err := reg.Push(context.Background(), recipientRef, "application/vnd.enbu.recipient.age.v1", []byte(kp.PublicKey), "tok", nil); err != nil {
		t.Fatalf("push recipient: %v", err)
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
	registry := &conflictOnceRegistry{Registry: a.Registry}
	a.Registry = registry

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

func TestPullSecrets_ErrorWhenNoPrivateKey(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "value"})

	// replace keystore with empty one (no private key)
	a.KeyStore = newMemKeyStore()

	_, _, _, err := a.PullSecrets(context.Background(), "default")
	if err == nil {
		t.Fatal("expected error when no private key")
	}
}

func TestPullSecrets_ErrorWhenWrongKey(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "value"})

	// replace stored key with a different identity (cannot decrypt)
	other := mustKeyPair(t)
	ks := newMemKeyStore()
	if err := ks.Store(KeystoreService, RepoKeystoreKey("owner", "repo"), []byte(other.Identity.String())); err != nil {
		t.Fatal(err)
	}
	a.KeyStore = ks

	_, _, _, err := a.PullSecrets(context.Background(), "default")
	if err == nil {
		t.Fatal("expected decryption error with wrong key")
	}
}

func TestPullSecretsToFile_WritesFile(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	if err := os.WriteFile("enbu.toml", []byte(`version = "v1alpha1"
default_env = "dev"
[env.dev]
output = ".env.dev"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "dev", kp, map[string]string{"SECRET": "mysecret"})

	if err := a.PullSecretsToFile(context.Background(), "dev"); err != nil {
		t.Fatalf("PullSecretsToFile: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".env.dev"))
	if err != nil {
		t.Fatalf("read .env.dev: %v", err)
	}
	if !strings.Contains(string(data), `SECRET="mysecret"`) {
		t.Fatalf("unexpected file content: %s", data)
	}
}

func TestPullSecretsToFile_ErrorWhenCannotDecrypt(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	_ = os.Chdir(dir)

	if err := os.WriteFile("enbu.toml", []byte(`version = "v1alpha1"
default_env = "dev"
[env.dev]
output = ".env.dev"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "dev", kp, map[string]string{"SECRET": "mysecret"})

	other := mustKeyPair(t)
	ks := newMemKeyStore()
	_ = ks.Store(KeystoreService, RepoKeystoreKey("owner", "repo"), []byte(other.Identity.String()))
	a.KeyStore = ks

	if err := a.PullSecretsToFile(context.Background(), "dev"); err == nil {
		t.Fatal("expected error when decryption fails")
	}
}

// compile-time check: age.KeyPair.Identity implements agecrypto.Identity
var _ agecrypto.Identity = (*agecrypto.X25519Identity)(nil)

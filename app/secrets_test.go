package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/bundle"
	"github.com/enbu-net/enbu/utils/keystore"
	"github.com/enbu-net/enbu/utils/oci"
)

// --- minimal test doubles ---

type memRegistry struct {
	mu   sync.RWMutex
	data map[string][]byte
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
		return nil, fmt.Errorf("%w: %s", oci.ErrNotFound, ref)
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
		return "", fmt.Errorf("%w: %s", oci.ErrNotFound, ref)
	}
	sum := sha256.Sum256(d)
	return fmt.Sprintf("sha256:%x", sum), nil
}

type staticTokenProvider struct{ token, username string }

func (s *staticTokenProvider) LoadToken() (string, string, error) { return s.token, s.username, nil }

type staticRepoDetector struct{ owner, repo string }

func (s *staticRepoDetector) LoadRepo() (string, string, error) { return s.owner, s.repo, nil }

type storeErrorSecretCache struct {
	SecretCache
	err error
}

func (c *storeErrorSecretCache) Store(string, []byte) error {
	return c.err
}

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
		return nil, keystore.ErrNotFound
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

// --- tests ---

func TestListSecrets_ReturnsStoredSecrets(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"FOO": "bar", "BAZ": "qux"})

	secrets, cached, err := a.ListSecretsWithCacheState(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListSecretsWithCacheState: %v", err)
	}
	if !cached {
		t.Fatal("cached = false, want true")
	}
	if secrets["FOO"] != "bar" || secrets["BAZ"] != "qux" {
		t.Fatalf("unexpected secrets: %v", secrets)
	}
}

func TestListSecrets_ReturnsEmptyMapWhenNoSecrets(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)

	secrets, cached, err := a.ListSecretsWithCacheState(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListSecretsWithCacheState: %v", err)
	}
	if cached {
		t.Fatal("cached = true, want false")
	}
	if len(secrets) != 0 {
		t.Fatalf("expected empty map, got: %v", secrets)
	}
}

func TestPullSecrets_UpdatesCache(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "value"})

	count, found, err := a.PullSecrets(context.Background(), "default")
	if err != nil {
		t.Fatalf("PullSecrets: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count=1, got %d", count)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	secrets, err := a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if secrets["KEY"] != "value" {
		t.Fatalf("cached secrets = %#v", secrets)
	}
}

func TestPullSecrets_NoRemoteSecretsRecordsEmptyCache(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)
	ref := a.secretsRef("owner", "repo", "default")
	if err := a.secretCache().Store(ref, []byte("stale")); err != nil {
		t.Fatal(err)
	}

	count, found, err := a.PullSecrets(context.Background(), "default")
	if err != nil {
		t.Fatalf("PullSecrets: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
	if found {
		t.Fatal("found = true, want false")
	}
	cached, err := a.secretCache().Load(ref)
	if err != nil {
		t.Fatalf("loading empty cache marker: %v", err)
	}
	if len(cached) != 0 {
		t.Fatalf("cached data = %q, want empty marker", cached)
	}
	secrets, cachedState, err := a.ListSecretsWithCacheState(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListSecretsWithCacheState: %v", err)
	}
	if !cachedState {
		t.Fatal("cached = false, want true after successful empty pull")
	}
	if len(secrets) != 0 {
		t.Fatalf("secrets = %v, want empty", secrets)
	}
}

func TestPullSecrets_EmptyCacheStoreErrorHasContext(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)
	a.SecretCache = &storeErrorSecretCache{
		SecretCache: newMemorySecretCache(),
		err:         errors.New("permission denied"),
	}

	_, _, err := a.PullSecrets(context.Background(), "default")
	if err == nil {
		t.Fatal("expected cache store error")
	}
	if !strings.Contains(err.Error(), "recording empty remote secrets: storing current state: permission denied") {
		t.Fatalf("error = %q", err)
	}
}

func TestPullThenExport_NoRemoteSecretsWritesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, ".env")
	if err := os.WriteFile(output, []byte("STALE=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)
	a.RepositoryDir = dir

	if _, _, err := a.PullSecrets(context.Background(), "default"); err != nil {
		t.Fatalf("PullSecrets: %v", err)
	}
	result, err := a.ExportSecretsToFile(context.Background(), "default")
	if err != nil {
		t.Fatalf("ExportSecretsToFile: %v", err)
	}
	if result.Count != 0 {
		t.Fatalf("export count = %d, want 0", result.Count)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("exported data = %q, want empty", data)
	}
}

func TestDeleteSecret_NoRemoteSecretsRecordsEmptyCache(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)
	ref := a.secretsRef("owner", "repo", "default")
	if err := a.secretCache().Store(ref, []byte("stale")); err != nil {
		t.Fatal(err)
	}

	if err := a.DeleteSecret(context.Background(), "default", "MISSING"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	cached, err := a.secretCache().Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) != 0 {
		t.Fatalf("cached data = %q, want empty marker", cached)
	}
}

func TestDeleteSecret_MissingKeyRefreshesCache(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"REMOTE": "current"})
	ref := a.secretsRef("owner", "repo", "default")

	stalePlaintext := bundle.Marshal(map[string]string{"STALE": "value"})
	staleCiphertext, err := age.EncryptForPublicKeys(stalePlaintext, []string{kp.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.secretCache().Store(ref, staleCiphertext); err != nil {
		t.Fatal(err)
	}

	if err := a.DeleteSecret(context.Background(), "default", "MISSING"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	secrets, err := a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if secrets["REMOTE"] != "current" {
		t.Fatalf("secrets = %v, want current remote state", secrets)
	}
	if _, ok := secrets["STALE"]; ok {
		t.Fatalf("stale secret remained cached: %v", secrets)
	}
}

func TestPullSecrets_ErrorWhenNoPrivateKey(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, map[string]string{"KEY": "value"})

	// replace keystore with empty one (no private key)
	a.KeyStore = newMemKeyStore()

	_, _, err := a.PullSecrets(context.Background(), "default")
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

	_, _, err := a.PullSecrets(context.Background(), "default")
	if err == nil {
		t.Fatal("expected decryption error with wrong key")
	}
}

func TestExportSecretsToFile_WritesFile(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, ".env.dev"), []byte("STALE=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := a.ExportSecretsToFile(context.Background(), "dev"); err != nil {
		t.Fatalf("ExportSecretsToFile: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".env.dev"))
	if err != nil {
		t.Fatalf("read .env.dev: %v", err)
	}
	if !strings.Contains(string(data), `SECRET="mysecret"`) {
		t.Fatalf("unexpected file content: %s", data)
	}
	info, err := os.Stat(filepath.Join(dir, ".env.dev"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("output mode = %o, want 600", got)
	}
}

func TestExportSecretsToFile_CacheMissPreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, ".env")
	const existing = "KEEP=existing\n"
	if err := os.WriteFile(output, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)
	a.RepositoryDir = dir

	if _, err := a.ExportSecretsToFile(context.Background(), "default"); err == nil {
		t.Fatal("expected cache miss")
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != existing {
		t.Fatalf("existing file was overwritten: got %q, want %q", data, existing)
	}
}

func TestEditSecret_NoRemoteSecretsReturnsMissingSecretError(t *testing.T) {
	kp := mustKeyPair(t)
	a := newTestApp(t, "owner", "repo", "default", kp, nil)

	err := a.EditSecret(context.Background(), "default", "MISSING", "value")
	if err == nil {
		t.Fatal("expected missing secret error")
	}
	if !strings.Contains(err.Error(), "secret MISSING does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "NAME_UNKNOWN") {
		t.Fatalf("raw registry error leaked: %v", err)
	}
}

func TestExportSecretsToFile_ErrorWhenCannotDecrypt(t *testing.T) {
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

	if _, err := a.ExportSecretsToFile(context.Background(), "dev"); err == nil {
		t.Fatal("expected error when decryption fails")
	}
}

// compile-time check: age.KeyPair.Identity implements agecrypto.Identity
var _ agecrypto.Identity = (*agecrypto.X25519Identity)(nil)

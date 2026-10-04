package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

type envRegistry struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newEnvRegistry() *envRegistry {
	return &envRegistry{data: make(map[string][]byte)}
}
func (e *envRegistry) Get(_ context.Context, key string) ([]byte, storage.Version, error) {
	if key == "enbu-workspace" {
		return workspaceObject(), "workspace", nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	data, ok := e.data[key]
	if !ok {
		return nil, "", storage.ErrNotFound
	}
	return append([]byte(nil), data...), storage.Version(fmt.Sprintf("sha256:%x", sha256.Sum256(data))), nil
}
func (e *envRegistry) Put(_ context.Context, key string, o []byte, v storage.Version) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var current storage.Version
	if data, ok := e.data[key]; ok {
		current = storage.Version(fmt.Sprintf("sha256:%x", sha256.Sum256(data)))
	}
	if current != v {
		return storage.ErrConflict
	}
	e.data[key] = append([]byte(nil), o...)
	return nil
}
func (e *envRegistry) List(_ context.Context, prefix string) ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var keys []string
	for key := range e.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func TestEnvironmentSecretsAreIsolated(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	config := `version = "v1alpha2"

[env.dev]
output = ".env.dev"

[env.prod]
output = ".env.prod"
`
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	reg := newEnvRegistry()
	a := &app.App{
		Storage:       storagetest.FromObjects(reg),
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities: &staticKeyStore{
			key: []byte(kp.Identity.String()),
		},
	}

	a.RepositoryDir = dir
	prepareCLIApp(t, a)
	if err := reg.Put(context.Background(), app.RecipientKey(kp.PublicKey), []byte(kp.PublicKey), ""); err != nil {
		t.Fatal(err)
	}

	devCmd := NewWithApp("test", a)
	devCmd.SetArgs([]string{"add", "--env", "dev", "API_KEY", "dev-secret"})
	if err := devCmd.Execute(); err != nil {
		t.Fatalf("add dev: %v", err)
	}

	prodCmd := NewWithApp("test", a)
	prodCmd.SetArgs([]string{"add", "--env", "prod", "API_KEY", "prod-secret"})
	if err := prodCmd.Execute(); err != nil {
		t.Fatalf("add prod: %v", err)
	}

	devOut := captureCommandStdout(t, func() {
		cmd := NewWithApp("test", a)
		cmd.SetArgs([]string{"pull", "--env", "dev", "--stdout"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("pull dev: %v", err)
		}
	})
	if !strings.Contains(devOut, "dev-secret") || strings.Contains(devOut, "prod-secret") {
		t.Fatalf("unexpected dev output: %s", devOut)
	}

	prodOut := captureCommandStdout(t, func() {
		cmd := NewWithApp("test", a)
		cmd.SetArgs([]string{"pull", "--env", "prod", "--stdout"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("pull prod: %v", err)
		}
	})
	if !strings.Contains(prodOut, "prod-secret") || strings.Contains(prodOut, "dev-secret") {
		t.Fatalf("unexpected prod output: %s", prodOut)
	}

	fileCmd := NewWithApp("test", a)
	fileCmd.SetArgs([]string{"pull", "--env", "dev"})
	if err := fileCmd.Execute(); err != nil {
		t.Fatalf("pull dev file: %v", err)
	}
	data, err := os.ReadFile(".env.dev")
	if err != nil {
		t.Fatalf("read .env.dev: %v", err)
	}
	if !strings.Contains(string(data), "dev-secret") || strings.Contains(string(data), "prod-secret") {
		t.Fatalf("unexpected .env.dev content: %s", data)
	}
}

func captureCommandStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	origStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = origStdout }()

	var buf bytes.Buffer
	readErr := make(chan error, 1)
	go func() {
		_, err := buf.ReadFrom(r)
		readErr <- err
	}()

	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	if err := <-readErr; err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	_ = r.Close()
	return buf.String()
}

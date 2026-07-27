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
	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/oci"
)

type envRegistry struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newEnvRegistry() *envRegistry {
	return &envRegistry{data: make(map[string][]byte)}
}

func (e *envRegistry) Push(_ context.Context, ref string, _ string, data []byte, _ string, _ *oci.PushOptions) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.data[ref] = append([]byte(nil), data...)
	return nil
}

func (e *envRegistry) Pull(_ context.Context, ref string, _ string) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	data, ok := e.data[ref]
	if !ok {
		return nil, fmt.Errorf("%w: %s", oci.ErrNotFound, ref)
	}
	return append([]byte(nil), data...), nil
}

func (e *envRegistry) ListTags(_ context.Context, ref string, _ string) ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	prefix := ref + ":"
	var tags []string
	for key := range e.data {
		if strings.HasPrefix(key, prefix) {
			tags = append(tags, strings.TrimPrefix(key, prefix))
		}
	}
	return tags, nil
}

func (e *envRegistry) GetDigest(_ context.Context, ref string, _ string) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	data, ok := e.data[ref]
	if !ok {
		return "", fmt.Errorf("%w: %s", oci.ErrNotFound, ref)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum), nil
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
	config := `version = "v1alpha1"

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
		Registry:      reg,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		KeyStore: &staticKeyStore{
			key: []byte(kp.Identity.String()),
		},
	}

	registryRef := "ghcr.io/owner/repo-enbu"
	ref := fmt.Sprintf("%s:%salice", registryRef, app.RecipientTagPrefix())
	if err := reg.Push(context.Background(), ref, "application/vnd.enbu.recipient.age.v1", []byte(kp.PublicKey), "token", nil); err != nil {
		t.Fatalf("push recipient: %v", err)
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

	for _, env := range []string{"dev", "prod"} {
		cmd := NewWithApp("test", a)
		cmd.SetArgs([]string{"pull", "--env", env})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("pull %s: %v", env, err)
		}
	}
	if _, err := os.Stat(".env.dev"); !os.IsNotExist(err) {
		t.Fatalf("pull created .env.dev: stat error = %v", err)
	}

	devOut := captureCommandStdout(t, func() {
		cmd := NewWithApp("test", a)
		cmd.SetArgs([]string{"export", "--env", "dev", "--stdout"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("export dev: %v", err)
		}
	})
	if !strings.Contains(devOut, "dev-secret") || strings.Contains(devOut, "prod-secret") {
		t.Fatalf("unexpected dev output: %s", devOut)
	}

	prodOut := captureCommandStdout(t, func() {
		cmd := NewWithApp("test", a)
		cmd.SetArgs([]string{"export", "dotenv", "--env", "prod", "--stdout"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("export prod: %v", err)
		}
	})
	if !strings.Contains(prodOut, "prod-secret") || strings.Contains(prodOut, "dev-secret") {
		t.Fatalf("unexpected prod output: %s", prodOut)
	}

	fileCmd := NewWithApp("test", a)
	fileCmd.SetArgs([]string{"export", "--env", "dev"})
	if err := fileCmd.Execute(); err != nil {
		t.Fatalf("export dev file: %v", err)
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

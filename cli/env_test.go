package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

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

	a := &app.App{
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities:    &staticKeyStore{},
		RepositoryDir: dir,
	}
	bootstrapCLIApp(t, a, storagetest.NewMemory())

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

package app

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

const testWorkspaceID = "11111111-1111-4111-8111-111111111111"

func newMemRegistry() storage.Store { return storagetest.NewMemory() }

type staticTokenProvider struct{ token, username string }

func (s *staticTokenProvider) LoadToken() (string, string, error) { return s.token, s.username, nil }

type staticRepoDetector struct{ owner, repo string }

func (s *staticRepoDetector) LoadRepo() (string, string, error) { return s.owner, s.repo, nil }

// newTestApp builds an App wired with in-memory doubles.
// It registers kp as both the recipient and the stored private key,
// and pushes a single secret under the given env if secrets != nil.
func newTestApp(t *testing.T, owner, repo, env string, kp *age.KeyPair, secrets map[string]string) *App {
	t.Helper()
	reg := newMemRegistry()
	ks := &apptest.Identities{}

	// store private key
	ks.Use(testWorkspaceID, kp.Identity, nil)

	a := &App{
		Storage:       reg,
		TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector:  &staticRepoDetector{owner: owner, repo: repo},
		Identities:    ks,
		CheckpointDir: t.TempDir(),
		CacheDir:      t.TempDir(),
	}

	prepareApp(t, a, env)
	// Bootstrap the workspace the way a real first device does: this creates the
	// signing key and the genesis Control, with kp as the founder's recipient.
	if _, err := a.InitializeRepository(context.Background(), InitOptions{}); err != nil {
		t.Fatalf("initialize workspace: %v", err)
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

func TestReadWorkspaceKeepsEnvironmentAndSecretsOnOneConfig(t *testing.T) {
	a := newAlice(t)
	if err := a.EditSecret(bg, "default", "KEY", "original"); err != nil {
		t.Fatal(err)
	}
	if err := a.CreateEnvironment("replacement"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddSecret(bg, "replacement", "KEY", "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := a.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	original := cfg.Environments["default"].Incarnation
	replacement := cfg.Environments["replacement"]
	cfg.Environments["default"] = replacement
	delete(cfg.Environments, "replacement")

	changed := false
	a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{
		OpenPayload: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
			if !changed {
				changed = true
				if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
					return nil, err
				}
			}
			return next.OpenPayload(ctx, kind, scope, rev)
		},
	})
	before, err := a.ReadWorkspace(bg)
	if err != nil || !changed || before.Environments[0].Incarnation != original || before.Secrets["KEY"] != "original" {
		t.Fatalf("initial snapshot: %+v %v", before, err)
	}
	after, err := a.ReadWorkspace(bg)
	if err != nil || after.Environments[0].Incarnation != replacement.Incarnation || after.Secrets["KEY"] != "replacement" {
		t.Fatalf("next snapshot: %+v %v", after, err)
	}
}

func TestReadWorkspaceSelectsAnExistingEnvironment(t *testing.T) {
	a := newAlice(t)
	if err := a.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := a.AddSecret(bg, "staging", "STAGE", "value"); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	delete(cfg.Environments, "default")
	cfg.DefaultEnv = ""
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.saveLocalState(cfg.WorkspaceID, &config.LocalConfig{}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.ReadWorkspace(bg)
	if err != nil || snapshot.Environment != "staging" || snapshot.Secrets["STAGE"] != "value" ||
		len(snapshot.Environments) != 1 || !snapshot.Environments[0].IsCurrent {
		t.Fatalf("unusable snapshot: %+v %v", snapshot, err)
	}
	envs, err := a.ListEnvironments()
	if err != nil || len(envs) != 1 || !envs[0].IsCurrent || envs[0].Name != snapshot.Environment {
		t.Fatalf("workspace and environment APIs disagree: %+v %v", envs, err)
	}
}

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
	ks := &apptest.Identities{}
	ks.Use(testWorkspaceID, other.Identity, nil)
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
	// Every test shares testWorkspaceID, so each device needs its own trust
	// root and checkpoints.
	if a.CheckpointDir == "" {
		a.CheckpointDir = t.TempDir()
	}
	cfg := config.NewProjectWithEnvironment(env)
	cfg.WorkspaceID = testWorkspaceID
	cfg.Storage.URL = "local:///unused"
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
}

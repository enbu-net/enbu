package app

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/storage"
)

type identityVault map[string][]byte

func (v identityVault) Store(_, key string, value []byte) error {
	v[key] = append([]byte(nil), value...)
	return nil
}
func (v identityVault) Load(_, key string) ([]byte, error) {
	b, ok := v[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}
func (v identityVault) Delete(_, key string) error { delete(v, key); return nil }

type registrationFailure struct {
	storage.Storage
	fail bool
}

func (r *registrationFailure) Put(ctx context.Context, key string, o storage.Object, v storage.Version) error {
	if r.fail && key != workspaceKey {
		return errors.New("registry offline")
	}
	return r.Storage.Put(ctx, key, o, v)
}

func TestInitializeReusesSavedIdentityAfterRegistrationFailure(t *testing.T) {
	manager := &identity.Manager{Dir: t.TempDir(), Mode: "keyring", Vault: identityVault{}}
	registry := &registrationFailure{Storage: newMemRegistry(), fail: true}
	a := &App{Storage: registry, Identities: manager, TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector: &staticRepoDetector{owner: "o", repo: "r"}, RepositoryDir: t.TempDir()}
	cfg := config.NewProjectWithEnvironment("default")
	cfg.WorkspaceID = testWorkspaceID
	cfg.Storage.URL = "local:///unused"
	if err := config.SaveProjectTo(a.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := a.InitializeRepository(context.Background()); err == nil {
		t.Fatal("registration should fail")
	}
	saved, err := manager.Info(testWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	registry.fail = false
	result, err := a.InitializeRepository(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PublicKey != saved.Recipient {
		t.Fatal("registration retry changed identity")
	}
	if len(manager.Vault.(identityVault)) != 1 {
		t.Fatal("registration retry created another key")
	}
}

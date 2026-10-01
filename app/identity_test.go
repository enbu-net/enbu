package app

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/oci"
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
	Registry
	fail bool
}

func (r *registrationFailure) Push(ctx context.Context, ref, media string, b []byte, token string, opts *oci.PushOptions) error {
	if r.fail {
		return errors.New("registry offline")
	}
	return r.Registry.Push(ctx, ref, media, b, token, opts)
}

func TestInitializeReusesSavedIdentityAfterRegistrationFailure(t *testing.T) {
	manager := &identity.Manager{Dir: t.TempDir(), Mode: "keyring", Vault: identityVault{}}
	registry := &registrationFailure{Registry: newMemRegistry(), fail: true}
	a := &App{Registry: registry, Identities: manager, TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector: &staticRepoDetector{owner: "o", repo: "r"}, RepositoryDir: t.TempDir()}
	if _, err := a.InitializeRepository(context.Background()); err == nil {
		t.Fatal("registration should fail")
	}
	saved, err := manager.Info("o", "r")
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

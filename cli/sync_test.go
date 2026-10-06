package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

type failingDigestRegistry struct {
	err error
}

func (f *failingDigestRegistry) Get(_ context.Context, key string) ([]byte, storage.Version, error) {
	if key == "enbu-workspace" {
		return workspaceObject(), "workspace", nil
	}
	return nil, "", f.err
}
func (f *failingDigestRegistry) Put(context.Context, string, []byte, storage.Version) error {
	return nil
}
func (f *failingDigestRegistry) List(context.Context, string) ([]string, error) { return nil, nil }

func TestSyncReturnsNonNotFoundSecretPullErrors(t *testing.T) {
	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	a := &app.App{
		Storage:       storagetest.FromObjects(&failingDigestRegistry{err: errors.New("unauthorized")}),
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities:    &staticKeyStore{key: []byte(kp.Identity.String())},
	}

	prepareCLIApp(t, a)
	err = a.SyncSecrets(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "pulling secrets") || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected pulling secrets unauthorized error, got %v", err)
	}
}

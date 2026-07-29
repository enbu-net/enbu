package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/oci"
)

type failingDigestRegistry struct {
	err error
}

func (f *failingDigestRegistry) Push(context.Context, string, string, []byte, string, *oci.PushOptions) error {
	return nil
}

func (f *failingDigestRegistry) Pull(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func (f *failingDigestRegistry) ListTags(context.Context, string, string) ([]string, error) {
	return nil, nil
}

func (f *failingDigestRegistry) GetDigest(context.Context, string, string) (string, error) {
	return "", f.err
}

func TestSyncReturnsNonNotFoundSecretPullErrors(t *testing.T) {
	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	a := &app.App{
		Registry:      &failingDigestRegistry{err: errors.New("unauthorized")},
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		KeyStore:      &staticKeyStore{key: []byte(kp.Identity.String())},
	}

	err = a.SyncSecrets(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "pulling secrets") || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected pulling secrets unauthorized error, got %v", err)
	}
}

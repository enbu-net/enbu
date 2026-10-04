package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

type deleteTestTokenProvider struct{}

func (*deleteTestTokenProvider) LoadToken() (string, string, error) { return "token", "alice", nil }

type deleteTestRepoDetector struct{}

func (*deleteTestRepoDetector) LoadRepo() (string, string, error) { return "owner", "repo", nil }

type deleteExpectedDigestRegistry struct {
	ciphertext     []byte
	publicKey      string
	expectedDigest string
	gotExpected    string
	pushes         int
	pushErr        error
}

func (r *deleteExpectedDigestRegistry) Get(_ context.Context, key string) ([]byte, storage.Version, error) {
	if key == "enbu-workspace" {
		return workspaceObject(), "workspace", nil
	}
	if strings.HasPrefix(key, "recipient-") {
		return []byte(r.publicKey), "recipient", nil
	}
	if r.ciphertext == nil {
		return nil, "", storage.ErrNotFound
	}
	return r.ciphertext, storage.Version(r.expectedDigest), nil
}
func (r *deleteExpectedDigestRegistry) List(context.Context, string) ([]string, error) {
	return []string{app.RecipientKey(r.publicKey)}, nil
}
func (r *deleteExpectedDigestRegistry) Put(_ context.Context, key string, o []byte, v storage.Version) error {
	if key == "enbu-workspace" {
		return nil
	}
	r.pushes++
	if r.pushes == 1 {
		r.gotExpected = string(v)
	}
	return r.pushErr
}

func TestDeleteCommandPassesBaseDigestToPush(t *testing.T) {
	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	plaintext := bundle.Marshal(map[string]string{"API_KEY": "secret"})
	ciphertext, err := age.EncryptForPublicKeys(plaintext, []string{kp.PublicKey})
	if err != nil {
		t.Fatalf("EncryptForPublicKeys: %v", err)
	}

	reg := &deleteExpectedDigestRegistry{
		ciphertext:     ciphertext,
		publicKey:      kp.PublicKey,
		expectedDigest: "sha256:base",
	}
	a := &app.App{
		Storage:       storagetest.FromObjects(reg),
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		Identities: &staticKeyStore{
			key: []byte(kp.Identity.String()),
		},
	}
	prepareCLIApp(t, a)
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"delete", "API_KEY"})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if reg.gotExpected != "sha256:base" {
		t.Fatalf("expected push to receive base digest, got %q", reg.gotExpected)
	}
	if reg.pushes != 2 {
		t.Fatalf("expected 2 push (main + snapshot), got %d", reg.pushes)
	}
}

type staticKeyStore struct {
	key []byte
}

func (s *staticKeyStore) storeSecret(_, _ string, value []byte) error {
	s.key = value
	return nil
}

func (s *staticKeyStore) loadSecret(string, string) ([]byte, error) {
	return s.key, nil
}

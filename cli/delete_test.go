//go:build legacy

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/internal/application"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/oci"
)

type deleteTestTokenProvider struct{}

func (d *deleteTestTokenProvider) LoadToken() (string, string, error) {
	return "token", "alice", nil
}

type deleteTestRepoDetector struct{}

func (d *deleteTestRepoDetector) LoadRepo() (string, string, error) {
	return "owner", "repo", nil
}

type deleteExpectedDigestRegistry struct {
	ciphertext     []byte
	publicKey      string
	expectedDigest string
	gotExpected    string
	pushes         int
	pushErr        error
}

func (d *deleteExpectedDigestRegistry) Push(_ context.Context, _ string, _ string, _ []byte, _ string, opts *oci.PushOptions) error {
	d.pushes++
	if d.pushes == 1 {
		if opts != nil {
			d.gotExpected = opts.ExpectedDigest
		}
	}
	return d.pushErr
}

func (d *deleteExpectedDigestRegistry) Pull(_ context.Context, ref string, _ string) ([]byte, error) {
	if strings.HasSuffix(ref, ":recipient-alice") {
		return []byte(d.publicKey), nil
	}
	return d.ciphertext, nil
}

func (d *deleteExpectedDigestRegistry) ListTags(context.Context, string, string) ([]string, error) {
	return []string{"recipient-alice"}, nil
}

func (d *deleteExpectedDigestRegistry) GetDigest(context.Context, string, string) (string, error) {
	return d.expectedDigest, nil
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
		Registry:      reg,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		KeyStore: &staticKeyStore{
			key: []byte(kp.Identity.String()),
		},
	}
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

func (s *staticKeyStore) Store(string, string, []byte) error {
	return nil
}

func (s *staticKeyStore) Load(string, string) ([]byte, error) {
	return s.key, nil
}

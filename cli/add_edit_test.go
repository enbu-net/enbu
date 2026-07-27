package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/bundle"
	"github.com/enbu-net/enbu/utils/oci"
)

type addEditRegistry struct {
	ciphertext     []byte
	publicKey      string
	expectedDigest string
	gotExpected    string
	pushes         int
}

func (a *addEditRegistry) Push(_ context.Context, _ string, _ string, data []byte, _ string, opts *oci.PushOptions) error {
	a.pushes++
	if a.pushes == 1 {
		if opts != nil {
			a.gotExpected = opts.ExpectedDigest
		}
		a.ciphertext = append([]byte(nil), data...)
	}
	return nil
}

func (a *addEditRegistry) Pull(_ context.Context, ref string, _ string) ([]byte, error) {
	if strings.HasSuffix(ref, ":recipient-alice") {
		return []byte(a.publicKey), nil
	}
	if a.ciphertext == nil {
		return nil, fmt.Errorf("%w: %s", oci.ErrNotFound, ref)
	}
	return append([]byte(nil), a.ciphertext...), nil
}

func (a *addEditRegistry) ListTags(context.Context, string, string) ([]string, error) {
	return []string{"recipient-alice"}, nil
}

func (a *addEditRegistry) GetDigest(_ context.Context, ref string, _ string) (string, error) {
	if a.ciphertext == nil {
		return "", fmt.Errorf("%w: %s", oci.ErrNotFound, ref)
	}
	return a.expectedDigest, nil
}

func TestAddCommandRejectsExistingSecret(t *testing.T) {
	kp, reg := newAddEditRegistry(t, map[string]string{"API_KEY": "old"})
	a := newAddEditApp(kp, reg)
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"add", "API_KEY", "new"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected duplicate add to fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	if reg.pushes != 0 {
		t.Fatalf("expected duplicate add not to push, got %d pushes", reg.pushes)
	}
}

func TestAddCommandCreatesNewSecret(t *testing.T) {
	kp, reg := newAddEditRegistry(t, nil)
	a := newAddEditApp(kp, reg)
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"add", "API_KEY", "secret"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("add: %v", err)
	}
	if reg.pushes != 2 {
		t.Fatalf("expected 2 push (main + snapshot), got %d", reg.pushes)
	}
	if reg.gotExpected != "" {
		t.Fatalf("expected empty base digest for initial add, got %q", reg.gotExpected)
	}

	secrets := decryptAddEditSecrets(t, kp, reg)
	if secrets["API_KEY"] != "secret" {
		t.Fatalf("expected API_KEY to be created, got %q", secrets["API_KEY"])
	}
}

func TestEditCommandUpdatesExistingSecret(t *testing.T) {
	kp, reg := newAddEditRegistry(t, map[string]string{"API_KEY": "old"})
	a := newAddEditApp(kp, reg)
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"edit", "API_KEY", "new"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if reg.pushes != 2 {
		t.Fatalf("expected 2 push (main + snapshot), got %d", reg.pushes)
	}
	if reg.gotExpected != "sha256:base" {
		t.Fatalf("expected base digest to be passed to push, got %q", reg.gotExpected)
	}

	secrets := decryptAddEditSecrets(t, kp, reg)
	if secrets["API_KEY"] != "new" {
		t.Fatalf("expected API_KEY to be edited, got %q", secrets["API_KEY"])
	}
}

func TestEditCommandRejectsMissingSecret(t *testing.T) {
	kp, reg := newAddEditRegistry(t, map[string]string{"OTHER": "value"})
	a := newAddEditApp(kp, reg)
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"edit", "API_KEY", "secret"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected missing edit to fail")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing error, got %v", err)
	}
	if reg.pushes != 0 {
		t.Fatalf("expected missing edit not to push, got %d pushes", reg.pushes)
	}
}

func newAddEditRegistry(t *testing.T, secrets map[string]string) (*age.KeyPair, *addEditRegistry) {
	t.Helper()

	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	reg := &addEditRegistry{
		publicKey:      kp.PublicKey,
		expectedDigest: "sha256:base",
	}
	if secrets != nil {
		plaintext := bundle.Marshal(secrets)
		ciphertext, err := age.EncryptForPublicKeys(plaintext, []string{kp.PublicKey})
		if err != nil {
			t.Fatalf("EncryptForPublicKeys: %v", err)
		}
		reg.ciphertext = ciphertext
	}

	return kp, reg
}

func newAddEditApp(kp *age.KeyPair, reg *addEditRegistry) *app.App {
	return &app.App{
		Registry:      reg,
		TokenProvider: &deleteTestTokenProvider{},
		RepoDetector:  &deleteTestRepoDetector{},
		KeyStore: &staticKeyStore{
			key: []byte(kp.Identity.String()),
		},
	}
}

func decryptAddEditSecrets(t *testing.T, kp *age.KeyPair, reg *addEditRegistry) map[string]string {
	t.Helper()

	plaintext, err := age.Decrypt(reg.ciphertext, kp.Identity)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	secrets, err := bundle.Unmarshal(plaintext)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return secrets
}

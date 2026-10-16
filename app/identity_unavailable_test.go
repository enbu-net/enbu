package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
)

type noIdentityBackend struct {
	*memKeyStore
	reason string
}

func (n *noIdentityBackend) Create(string) (identity.Identity, identity.PublicInfo, string, error) {
	return nil, identity.PublicInfo{}, "", fmt.Errorf("%w: hardware identity unavailable: %s", identity.ErrUnavailable, n.reason)
}

type noSignerBackend struct {
	*memKeyStore
}

func (n *noSignerBackend) CreateSigner(string) (signing.Signer, identity.SignerInfo, string, error) {
	return nil, identity.SignerInfo{}, "", fmt.Errorf("%w: OS keyring unavailable: timed out", identity.ErrUnavailable)
}

// init says why no identity could be made, with the same reason doctor shows,
// instead of an internal error.
func TestInitReportsAnUnusableIdentityBackend(t *testing.T) {
	for name, store := range map[string]IdentityStore{
		"encryption identity": &noIdentityBackend{memKeyStore: newMemKeyStore(), reason: "open /dev/tpmrm0: permission denied"},
		"signing key":         &noSignerBackend{memKeyStore: newMemKeyStore()},
	} {
		t.Run(name, func(t *testing.T) {
			a := &App{Storage: newMemRegistry(), TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
				RepoDetector: &staticRepoDetector{owner: "o", repo: "r"}, Identities: store, CheckpointDir: t.TempDir()}
			prepareApp(t, a, "default")
			_, err := a.InitializeRepository(bg)
			if !apperr.Is(err, apperr.CodeIdentityUnavailable) {
				t.Fatalf("code = %v, want identity_unavailable", err)
			}
			var appErr *apperr.Error
			if !errors.As(err, &appErr) || appErr.Params()["reason"] == "" {
				t.Fatalf("no reason for the user: %v", err)
			}
			if !errors.Is(err, identity.ErrUnavailable) {
				t.Fatalf("cause lost: %v", err)
			}
		})
	}
}

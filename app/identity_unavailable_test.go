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
	return nil, identity.PublicInfo{}, "", &identity.UnavailableError{Reason: "hardware identity unavailable: " + n.reason}
}

type noSignerBackend struct {
	*memKeyStore
}

func (n *noSignerBackend) CreateSigner(string) (signing.Signer, identity.SignerInfo, string, error) {
	return nil, identity.SignerInfo{}, "", &identity.UnavailableError{Reason: "OS keyring unavailable: timed out"}
}

// init says why no identity could be made, with the same reason doctor shows,
// instead of an internal error.
func TestInitReportsAnUnusableIdentityBackend(t *testing.T) {
	for name, store := range unusableBackends() {
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

// unusableBackends are the stores that cannot create a key, by what fails.
func unusableBackends() map[string]IdentityStore {
	return map[string]IdentityStore{
		"encryption identity": &noIdentityBackend{memKeyStore: newMemKeyStore(), reason: "open /dev/tpmrm0: permission denied"},
		"signing key":         &noSignerBackend{memKeyStore: newMemKeyStore()},
	}
}

// requireIdentityUnavailable checks that err tells the user why, keeping the cause.
func requireIdentityUnavailable(t *testing.T, err error, reason string) {
	t.Helper()
	if !apperr.Is(err, apperr.CodeIdentityUnavailable) {
		t.Fatalf("code = %v, want identity_unavailable", err)
	}
	var appErr *apperr.Error
	if !errors.As(err, &appErr) || appErr.Params()["reason"] != reason {
		t.Fatalf("reason = %q, want %q (%v)", appErr.Params()["reason"], reason, err)
	}
	if !errors.Is(err, identity.ErrUnavailable) {
		t.Fatalf("cause lost: %v", err)
	}
}

// 'enbu identity create' reports an unusable backend the same way init does.
func TestCreateIdentityReportsAnUnusableIdentityBackend(t *testing.T) {
	reasons := map[string]string{
		"encryption identity": "hardware identity unavailable: open /dev/tpmrm0: permission denied",
		"signing key":         "OS keyring unavailable: timed out",
	}
	for name, store := range unusableBackends() {
		t.Run(name, func(t *testing.T) {
			a := &App{Identities: store}
			prepareApp(t, a, "default")
			_, _, err := a.CreateIdentity()
			requireIdentityUnavailable(t, err, reasons[name])
		})
	}
}

type lostBackend struct {
	*memKeyStore
	signer bool
}

func (l *lostBackend) Load(workspaceID string) (identity.Identity, error) {
	if !l.signer {
		return nil, &identity.UnavailableError{Reason: "saved hardware backend unavailable"}
	}
	return l.memKeyStore.Load(workspaceID)
}

func (l *lostBackend) LoadSigner(workspaceID string) (signing.Signer, error) {
	if l.signer {
		return nil, &identity.UnavailableError{Reason: "keyring unavailable", Err: fmt.Errorf("dbus: no reply")}
	}
	return l.memKeyStore.LoadSigner(workspaceID)
}

// A device whose saved key can no longer be reached says so on every
// operation, not only init, and the reason does not repeat the sentinel.
func TestLoadingAnUnreachableIdentityReportsWhy(t *testing.T) {
	for name, tc := range map[string]struct {
		signer bool
		reason string
	}{
		"encryption identity": {false, "saved hardware backend unavailable"},
		"signing key":         {true, "keyring unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			keys := newMemKeyStore()
			a := &App{Storage: newMemRegistry(), TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
				RepoDetector: &staticRepoDetector{owner: "o", repo: "r"}, Identities: keys, CheckpointDir: t.TempDir()}
			prepareApp(t, a, "default")
			if _, err := a.InitializeRepository(bg); err != nil {
				t.Fatal(err)
			}
			a.Identities = &lostBackend{memKeyStore: keys, signer: tc.signer}
			_, err := a.openSession(bg)
			requireIdentityUnavailable(t, err, tc.reason)
		})
	}
}

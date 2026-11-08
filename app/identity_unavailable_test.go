package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
)

type noIdentityBackend struct {
	*apptest.Identities
	reason string
}

func (n *noIdentityBackend) Create(string) (*identity.Device, identity.PublicInfo, string, error) {
	return nil, identity.PublicInfo{}, "", &identity.UnavailableError{Reason: n.reason}
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
		"hardware": &noIdentityBackend{Identities: &apptest.Identities{}, reason: "hardware identity unavailable: open /dev/tpmrm0: permission denied"},
		"keyring":  &noIdentityBackend{Identities: &apptest.Identities{}, reason: "OS keyring unavailable: timed out"},
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
		"hardware": "hardware identity unavailable: open /dev/tpmrm0: permission denied",
		"keyring":  "OS keyring unavailable: timed out",
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

type lostBackend struct{ *apptest.Identities }

func (lostBackend) Load(string) (*identity.Device, error) {
	return nil, &identity.UnavailableError{Reason: "keyring unavailable", Err: fmt.Errorf("dbus: no reply")}
}

func (lostBackend) Info(string) (identity.PublicInfo, error) {
	return identity.PublicInfo{}, &identity.UnavailableError{Reason: "keyring unavailable"}
}

// A device whose saved keys can no longer be reached says so on every
// operation, not only init, and the reason does not repeat the sentinel.
func TestLoadingAnUnreachableIdentityReportsWhy(t *testing.T) {
	keys := &apptest.Identities{}
	a := &App{Storage: newMemRegistry(), TokenProvider: &staticTokenProvider{token: "tok", username: "alice"},
		RepoDetector: &staticRepoDetector{owner: "o", repo: "r"}, Identities: keys, CheckpointDir: t.TempDir()}
	prepareApp(t, a, "default")
	if _, err := a.InitializeRepository(bg); err != nil {
		t.Fatal(err)
	}
	a.Identities = lostBackend{keys}
	_, err := a.openSession(bg)
	requireIdentityUnavailable(t, err, "keyring unavailable")
	_, err = a.IdentityInfo()
	requireIdentityUnavailable(t, err, "keyring unavailable")
}

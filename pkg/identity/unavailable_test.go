package identity

import (
	"errors"
	"io/fs"
	"testing"
)

func TestUnavailableCarriesTheReasonAndTheCause(t *testing.T) {
	cause := errors.New("dbus: no reply")
	err := unavailable("OS keyring unavailable", cause)
	var u *UnavailableError
	if !errors.As(err, &u) || u.Reason != "OS keyring unavailable: dbus: no reply" {
		t.Fatalf("reason = %+v", u)
	}
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, cause) {
		t.Fatalf("errors.Is lost the sentinel or the cause: %v", err)
	}
	if got, want := err.Error(), "identity backend unavailable: OS keyring unavailable: dbus: no reply"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if u := unavailable("keyring unavailable", nil).(*UnavailableError); u.Reason != "keyring unavailable" || u.Unwrap() != nil {
		t.Fatalf("without a cause: %+v", u)
	}
}

type brokenVault struct{ memoryVault }

var errNoReply = errors.New("dbus: no reply")

func (brokenVault) Store(string, string, []byte) error { return errNoReply }

type lockedVault struct{ memoryVault }

func (lockedVault) Load(string, string) ([]byte, error) { return nil, errNoReply }

// A keyring that answered the probe but then fails to store or load the key
// is reported as unavailable; an entry that is simply missing is not.
func TestKeyringFailuresAreUnavailable(t *testing.T) {
	m := &Manager{Dir: t.TempDir(), Mode: "keyring", Vault: brokenVault{memoryVault{}}}
	if _, _, _, err := m.Create("ws"); !errors.Is(err, ErrUnavailable) || !errors.Is(err, errNoReply) {
		t.Fatalf("Create with a failing store = %v", err)
	}
	if _, _, _, err := m.CreateSigner("ws"); !errors.Is(err, ErrUnavailable) || !errors.Is(err, errNoReply) {
		t.Fatalf("CreateSigner with a failing store = %v", err)
	}

	vault := memoryVault{}
	m = &Manager{Dir: t.TempDir(), Mode: "keyring", Vault: vault}
	if _, _, _, err := m.Create("ws"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.CreateSigner("ws"); err != nil {
		t.Fatal(err)
	}
	m.Vault = lockedVault{vault}
	if _, err := m.Load("ws"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Load from a locked keyring = %v", err)
	}
	if _, err := m.LoadSigner("ws"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("LoadSigner from a locked keyring = %v", err)
	}
	m.Vault = nil
	if _, err := m.Load("ws"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Load without a keyring = %v", err)
	}
	m.Vault = memoryVault{}
	if _, err := m.Load("ws"); errors.Is(err, ErrUnavailable) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load of a missing entry = %v, want fs.ErrNotExist and not unavailable", err)
	}
	if _, err := m.LoadSigner("ws"); errors.Is(err, ErrUnavailable) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadSigner of a missing entry = %v, want fs.ErrNotExist and not unavailable", err)
	}
}

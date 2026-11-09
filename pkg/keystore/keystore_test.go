package keystore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/zalando/go-keyring"
)

var defaultProbe = probeKeyring

// stubProbe replaces the OS keyring check, which would otherwise talk to the
// real Secret Service, for tests that mock go-keyring.
func stubProbe(t *testing.T, err error) {
	t.Helper()
	probeKeyring = func(context.Context) error { return err }
	t.Cleanup(func() { probeKeyring = defaultProbe })
}

func TestKeyringBackendDeleteMissing(t *testing.T) {
	keyring.MockInit()
	stubProbe(t, nil)
	backend := &KeyringBackend{}

	err := backend.Delete("svc", "missing")

	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete() error = %v, want fs.ErrNotExist", err)
	}
}

// A locked keyring fails every operation with ErrLocked before go-keyring
// could wait on an unlock prompt, on Linux where that prompt can hang.
func TestKeyringBackendRefusesALockedKeyring(t *testing.T) {
	if !checkBeforeUse {
		t.Skip("only Linux checks the keyring before each operation")
	}
	keyring.MockInit()
	stubProbe(t, fmt.Errorf("%w: test", ErrLocked))
	b := &KeyringBackend{}
	if err := b.Store("svc", "k", []byte("v")); !errors.Is(err, ErrLocked) {
		t.Fatalf("Store = %v, want ErrLocked", err)
	}
	if _, err := b.Load("svc", "k"); !errors.Is(err, ErrLocked) {
		t.Fatalf("Load = %v, want ErrLocked", err)
	}
	if err := b.Delete("svc", "k"); !errors.Is(err, ErrLocked) {
		t.Fatalf("Delete = %v, want ErrLocked", err)
	}
	if err := b.Probe(context.Background()); !errors.Is(err, ErrLocked) {
		t.Fatalf("Probe = %v, want ErrLocked", err)
	}
}

// New is always the OS keyring, even when the keyring is missing: there is
// no plaintext file to fall back to.
func TestNewIsTheOSKeyring(t *testing.T) {
	stubProbe(t, fmt.Errorf("%w: test", ErrNoKeyring))
	b := New()
	if _, ok := b.(*KeyringBackend); !ok {
		t.Fatalf("New() = %T, want *KeyringBackend", b)
	}
	if _, err := b.Load("svc", "k"); checkBeforeUse && !errors.Is(err, ErrNoKeyring) {
		t.Fatalf("Load without a keyring = %v", err)
	}
}

// The probe gives up when its context ends, even if the keyring never
// answers.
func TestProbeStopsAtTheTimeout(t *testing.T) {
	probeKeyring = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	t.Cleanup(func() { probeKeyring = defaultProbe })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&KeyringBackend{}).Probe(ctx); err == nil {
		t.Fatal("Probe with an ended context succeeded")
	}
}

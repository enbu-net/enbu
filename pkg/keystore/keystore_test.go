package keystore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/pkg/config"
	"github.com/zalando/go-keyring"
)

func TestNew_ExplicitText(t *testing.T) {
	t.Setenv("ENBU_BACKEND", "text")
	b, err := New()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*TextBackend); !ok {
		t.Fatalf("expected *TextBackend, got %T", b)
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	t.Setenv("ENBU_BACKEND", "invalid")
	_, err := New()
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

var defaultProbe = probeKeyring

// stubProbe replaces the OS keyring check, which would otherwise talk to the
// real Secret Service, for tests that mock go-keyring.
func stubProbe(t *testing.T, err error) {
	t.Helper()
	probeKeyring = func(context.Context) error { return err }
	t.Cleanup(func() { probeKeyring = defaultProbe })
}

func TestNew_DefaultBackend(t *testing.T) {
	keyring.MockInit()
	t.Setenv("ENBU_BACKEND", "")
	b, err := New()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*KeyringBackend); !ok {
		t.Fatalf("expected *KeyringBackend, got %T", b)
	}
}

func TestNew_KeyringAvailableFallbackNotTriggered(t *testing.T) {
	keyring.MockInit()
	t.Setenv("ENBU_BACKEND", "keyring")
	b, err := New()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*KeyringBackend); !ok {
		t.Fatalf("expected *KeyringBackend when mock is healthy, got %T", b)
	}
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

// New never swaps a missing keyring for a plaintext file: only
// ENBU_BACKEND=text does that.
func TestNew_DoesNotFallBackToText(t *testing.T) {
	stubProbe(t, fmt.Errorf("%w: test", ErrNoKeyring))
	t.Setenv("ENBU_BACKEND", "")
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.(*KeyringBackend); !ok {
		t.Fatalf("New() = %T, want *KeyringBackend", b)
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

func TestTextBackend_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENBU_TEXT_BACKEND_DIR", dir)

	tb := &TextBackend{}

	if err := tb.Store("svc", "key1", []byte("secret")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := tb.Load("svc", "key1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("expected %q, got %q", "secret", got)
	}

	if err := tb.Delete("svc", "key1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = tb.Load("svc", "key1")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist after delete, got %v", err)
	}
}

func TestTextBackend_LoadNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENBU_TEXT_BACKEND_DIR", dir)

	tb := &TextBackend{}
	_, err := tb.Load("svc", "nonexistent")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestTextBackend_DeleteNonExistent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENBU_TEXT_BACKEND_DIR", dir)

	tb := &TextBackend{}
	if err := tb.Delete("svc", "nonexistent"); err != nil {
		t.Fatalf("Delete of nonexistent should not error, got %v", err)
	}
}

func TestTextBackendDirFollowsDataDir(t *testing.T) {
	t.Setenv("ENBU_TEXT_BACKEND_DIR", "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	if got, want := textBackendDir(), filepath.Join(config.DataDir(), "keys"); got != want {
		t.Fatalf("textBackendDir() = %q, want %q", got, want)
	}
	t.Setenv("ENBU_TEXT_BACKEND_DIR", "/custom")
	if got := textBackendDir(); got != "/custom" {
		t.Fatalf("textBackendDir() = %q, want the override", got)
	}
}

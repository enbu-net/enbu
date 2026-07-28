package keystore

import (
	"errors"
	"io/fs"
	"testing"

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

func TestNew_KeyringUnavailableFallsBackToText(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	t.Setenv("ENBU_BACKEND", "keyring")
	b, err := New()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := b.(*TextBackend); !ok {
		t.Fatalf("expected *TextBackend on probe failure, got %T", b)
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

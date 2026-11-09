package identity

import (
	"bytes"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/jonboulle/clockwork"
)

type expiryClock struct {
	clock.Clock
	expired chan struct{}
}

func (c expiryClock) AfterFunc(d time.Duration, f func()) clockwork.Timer {
	return c.Clock.AfterFunc(d, func() { f(); close(c.expired) })
}

func TestTPMAuthClockWipesUnusedSecret(t *testing.T) {
	c := clockwork.NewFakeClock()
	done := make(chan struct{})
	b := &TPMBackend{Clock: expiryClock{Clock: c, expired: done}, Verifier: &fakeVerifier{secret: bytes.Repeat([]byte{7}, 32)}}
	if _, _, err := b.enrollAuth(); err != nil {
		t.Fatal(err)
	}
	previous := b.auth.value
	c.Advance(authTTL)
	<-done
	b.auth.mu.Lock()
	defer b.auth.mu.Unlock()
	if b.auth.value != nil || !bytes.Equal(previous, make([]byte, len(previous))) {
		t.Fatal("expiry did not clear the unused cached secret")
	}
}

func TestTPMAuthExactTTLRequiresVerification(t *testing.T) {
	c := clockwork.NewFakeClock()
	verifier := &fakeVerifier{secret: bytes.Repeat([]byte{7}, 32)}
	b := &TPMBackend{Clock: c, Verifier: verifier}
	credential, _, err := b.enrollAuth()
	if err != nil {
		t.Fatal(err)
	}
	c.Advance(authTTL - time.Nanosecond)
	if _, err := b.authFor(credential); err != nil || verifier.asks != 0 {
		t.Fatalf("cache expired early: %v", err)
	}
	c.Advance(time.Nanosecond)
	if _, err := b.authFor(credential); err != nil || verifier.asks != 1 {
		t.Fatalf("cache survived exact expiry: %v", err)
	}
}

func TestManagerPassesClockToKeyStores(t *testing.T) {
	c := clockwork.NewFakeClock()
	m := New(c)
	if m.Vault.(*keystore.KeyringBackend).Clock != c {
		t.Fatal("keyring received another clock")
	}
	if backend, ok := m.Hardware.(*TPMBackend); ok && backend.Clock != c {
		t.Fatal("TPM received another clock")
	}
}

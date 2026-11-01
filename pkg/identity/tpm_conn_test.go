package identity

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// countingTPM counts the TPM opens and the CreatePrimary commands of a backend.
type countingTPM struct {
	mu        sync.Mutex
	opens     int
	primaries int
	open      int // connections not closed yet
}

func (c *countingTPM) backend(t *testing.T) *TPMBackend {
	t.Helper()
	v := newVirtualTPM(t)
	return &TPMBackend{Device: "test", plainSessions: true, Open: func() (transport.TPMCloser, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.opens++
		c.open++
		return &countedTransport{counter: c, inner: &virtualTransport{v}}, nil
	}}
}

type countedTransport struct {
	counter *countingTPM
	inner   transport.TPMCloser
}

func (t *countedTransport) Send(cmd []byte) ([]byte, error) {
	if len(cmd) >= 10 && tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10])) == tpm2.TPMCCCreatePrimary {
		t.counter.mu.Lock()
		t.counter.primaries++
		t.counter.mu.Unlock()
	}
	return t.inner.Send(cmd)
}

func (t *countedTransport) Close() error {
	t.counter.mu.Lock()
	t.counter.open--
	t.counter.mu.Unlock()
	return t.inner.Close()
}

// TestTPMKeysShareOneConnection loads what one operation needs (the hybrid
// identity, whose seed is unsealed, and the signing key) and checks that the
// TPM is opened and the storage primary created only once, then released.
func TestTPMKeysShareOneConnection(t *testing.T) {
	counter := &countingTPM{}
	b := counter.backend(t)
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: b}
	id, _, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	s, _, _, err := m.CreateSigner("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	_ = id.Close()
	if counter.open != 0 {
		t.Fatalf("%d TPM connections left open after closing every key", counter.open)
	}

	counter.opens, counter.primaries = 0, 0
	id, err = m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	s, err = m.LoadSigner("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if counter.opens != 1 || counter.primaries != 1 {
		t.Fatalf("loading identity, sealed seed and signer: %d opens and %d primaries, want 1 and 1", counter.opens, counter.primaries)
	}
	if _, err := s.Sign(signing.DomainState, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := id.Close(); err != nil {
		t.Fatal(err)
	}
	// The signer still holds the connection, so it keeps working.
	if _, err := s.Sign(signing.DomainState, []byte("y")); err != nil {
		t.Fatalf("signer after the identity closed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if counter.open != 0 {
		t.Fatalf("%d TPM connections left open", counter.open)
	}
	// A later operation opens the TPM again.
	id, err = m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if counter.opens != 2 {
		t.Fatalf("opens = %d after reloading, want 2", counter.opens)
	}
}

// TestTPMKeysUseOneConnectionConcurrently runs ECDH and signatures from
// several goroutines over the shared connection; the race detector and the
// TPM's session checks catch interleaved commands.
func TestTPMKeysUseOneConnectionConcurrently(t *testing.T) {
	b := (&countingTPM{}).backend(t)
	id, _, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	s, _, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	key := id.(*taggedIdentity).key
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := key.ECDH(key.PublicKey()); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := s.Sign(signing.DomainState, []byte("x")); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestTPMRefusesAnotherStoragePrimary(t *testing.T) {
	b := (&countingTPM{}).backend(t)
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if len(md.TPMParentName) == 0 {
		t.Fatal("Create did not pin the storage primary")
	}
	s, smd, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if !bytes.Equal(smd.TPMParentName, md.TPMParentName) {
		t.Fatal("signer pinned another storage primary")
	}
	bad := *md
	bad.TPMParentName = []byte("another primary")
	if _, err := b.Load(&bad); err == nil || !strings.Contains(err.Error(), "storage primary") {
		t.Fatalf("Load with another pinned primary: %v", err)
	}
	badSigner := *smd
	badSigner.TPMParentName = []byte("another primary")
	if _, err := b.LoadSigner(&badSigner); err == nil {
		t.Fatal("LoadSigner accepted another pinned primary")
	}
	seed := make([]byte, 64)
	if err := b.SealSeed(&bad, seed); err == nil {
		t.Fatal("SealSeed accepted another pinned primary")
	}
	if b.conn != nil {
		t.Fatal("a refused key left the connection open")
	}
}

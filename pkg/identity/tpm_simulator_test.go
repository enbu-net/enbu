//go:build linux && cgo

package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
)

// recordingTPM keeps every response of the reference TPM simulator, which,
// unlike the virtual TPM of the other tests, implements parameter encryption.
type recordingTPM struct {
	mu        sync.Mutex
	inner     transport.TPM
	responses [][]byte
}

func (r *recordingTPM) Send(cmd []byte) ([]byte, error) {
	rsp, err := r.inner.Send(cmd)
	r.mu.Lock()
	r.responses = append(r.responses, append([]byte(nil), rsp...))
	r.mu.Unlock()
	return rsp, err
}

func (r *recordingTPM) Close() error { return nil }

func (r *recordingTPM) sawInClear(secret []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rsp := range r.responses {
		if bytes.Contains(rsp, secret) {
			return true
		}
	}
	return false
}

// TestTPMSimulatorEncryptsSecretsOnTheBus runs the identity, the sealed seed
// and the signer with parameter encryption on, and checks that neither the
// ECDH shared secret nor the ML-KEM seed appears in a TPM response.
func TestTPMSimulatorEncryptsSecretsOnTheBus(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sim.Close() }()
	rec := &recordingTPM{inner: transport.FromReadWriter(sim)}
	b := &TPMBackend{Device: "simulator", Open: func() (transport.TPMCloser, error) { return rec, nil }}
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()

	key := id.(*taggedIdentity).key
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := key.ECDH(peer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	want, err := peer.ECDH(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, want) {
		t.Fatal("TPM ECDH result differs from the software one")
	}
	if rec.sawInClear(shared) {
		t.Fatal("the ECDH shared secret crossed the bus in the clear")
	}

	seed := make([]byte, mlkem.SeedSize)
	_, _ = rand.Read(seed)
	if err := b.SealSeed(md, seed); err != nil {
		t.Fatal(err)
	}
	got, err := b.UnsealSeed(md)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("unseal: %v", err)
	}
	if rec.sawInClear(seed) {
		t.Fatal("the ML-KEM seed crossed the bus in the clear")
	}

	ct, err := age.EncryptForPublicKeys([]byte("simulated"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := age.Decrypt(ct, id); err != nil || string(out) != "simulated" {
		t.Fatalf("decrypt: %q %v", out, err)
	}
	s, _, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	sig, err := s.Sign(signing.DomainState, []byte("state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Verify(s.Public(), signing.DomainState, []byte("state"), sig); err != nil {
		t.Fatal(err)
	}
}

//go:build linux && cgo

package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
)

// recordingTPM keeps every command and response of the reference TPM
// simulator, which, unlike the virtual TPM of the other tests, implements
// parameter encryption.
type recordingTPM struct {
	mu      sync.Mutex
	inner   transport.TPM
	traffic [][]byte
}

func (r *recordingTPM) Send(cmd []byte) ([]byte, error) {
	// Copy the command first: the simulator decrypts its parameter in place.
	sent := append([]byte(nil), cmd...)
	rsp, err := r.inner.Send(cmd)
	r.mu.Lock()
	r.traffic = append(r.traffic, sent, append([]byte(nil), rsp...))
	r.mu.Unlock()
	return rsp, err
}

func (r *recordingTPM) Close() error { return nil }

func (r *recordingTPM) sawInClear(secret []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, msg := range r.traffic {
		if bytes.Contains(msg, secret) {
			return true
		}
	}
	return false
}

// TestTPMSimulatorEncryptsSecretsOnTheBus runs a device with parameter
// encryption and checks that the ECDH shared secret does not cross the bus in
// the clear. The ML-KEM seed never reaches the TPM: it is sealed to the ECDH
// key on the host.
func TestTPMSimulatorEncryptsSecretsOnTheBus(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sim.Close() }()
	rec := &recordingTPM{inner: transport.FromReadWriter(sim)}
	b := &TPMBackend{Device: "simulator", Open: func() (transport.TPMCloser, error) { return rec, nil }}
	key, s, err := b.Create(&Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = key.Close(); _ = s.Close() }()
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
	sig, err := s.Sign(signing.DomainState, []byte("state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Verify(s.Public(), signing.DomainState, []byte("state"), sig); err != nil {
		t.Fatal(err)
	}
}

package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"testing"
)

// BenchmarkSignatureSchemes compares today's signing keys with ML-DSA-65, a
// candidate post-quantum replacement. It is a measurement only: ML-DSA is not
// a signing Algorithm. The message is the size of a typical signed State.
func BenchmarkSignatureSchemes(b *testing.B) {
	msg := make([]byte, 512)
	_, _ = rand.Read(msg)
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p256, _ := NewP256Signer(pk)
	mk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		b.Fatal(err)
	}
	opts := &mldsa.Options{Context: DomainState}

	type scheme struct {
		name          string
		publicKeySize int
		sign          func() ([]byte, error)
		verify        func(sig []byte) bool
	}
	edSigner := NewEd25519Signer(ek)
	for _, s := range []scheme{
		{"ed25519", ed25519.PublicKeySize,
			func() ([]byte, error) { return edSigner.Sign(DomainState, msg) },
			func(sig []byte) bool { return Verify(edSigner.Public(), DomainState, msg, sig) == nil }},
		{"p256", len(p256.Public().Bytes),
			func() ([]byte, error) { return p256.Sign(DomainState, msg) },
			func(sig []byte) bool { return Verify(p256.Public(), DomainState, msg, sig) == nil }},
		{"mldsa65", mldsa.MLDSA65PublicKeySize,
			func() ([]byte, error) { return mk.Sign(rand.Reader, msg, opts) },
			func(sig []byte) bool { return mldsa.Verify(mk.PublicKey(), msg, sig, opts) == nil }},
	} {
		sig, err := s.sign()
		if err != nil || !s.verify(sig) {
			b.Fatalf("%s: %v", s.name, err)
		}
		b.Run(s.name+"/sign", func(b *testing.B) {
			for b.Loop() {
				if _, err := s.sign(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(sig)), "sig-bytes")
			b.ReportMetric(float64(s.publicKeySize), "pubkey-bytes")
		})
		b.Run(s.name+"/verify", func(b *testing.B) {
			for b.Loop() {
				if !s.verify(sig) {
					b.Fatal("verify failed")
				}
			}
		})
	}
}

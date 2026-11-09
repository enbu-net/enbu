package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"pgregory.net/rapid"
)

// CRYPTO-1 and CRYPTO-3.

func testSigners(t testing.TB) []Signer {
	t.Helper()
	_, ek, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewP256Signer(pk)
	if err != nil {
		t.Fatal(err)
	}
	return []Signer{NewEd25519Signer(ek), p}
}

func flip(b []byte, bit int) []byte {
	out := append([]byte(nil), b...)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

// TestSignaturesRejectEveryBitFlip flips every bit of the body and of the
// signature, swaps the domain and the key, and requires every variant to fail.
func TestSignaturesRejectEveryBitFlip(t *testing.T) {
	signers := testSigners(t)
	body := []byte("enbu signed body: workspace, parents, generation")
	for _, s := range signers {
		sig, err := s.Sign(DomainState, body)
		if err != nil {
			t.Fatal(err)
		}
		pub := s.Public()
		if err := Verify(pub, DomainState, body, sig); err != nil {
			t.Fatalf("%s: the signature does not verify: %v", pub.Alg, err)
		}
		for bit := range len(body) * 8 {
			if Verify(pub, DomainState, flip(body, bit), sig) == nil {
				t.Fatalf("%s: body with bit %d flipped verifies", pub.Alg, bit)
			}
		}
		for bit := range len(sig) * 8 {
			if Verify(pub, DomainState, body, flip(sig, bit)) == nil {
				t.Fatalf("%s: signature with bit %d flipped verifies", pub.Alg, bit)
			}
		}
		for _, d := range []string{DomainControl, DomainJoin, DomainState + "x", ""} {
			if Verify(pub, d, body, sig) == nil {
				t.Fatalf("%s: a %s signature verifies for domain %q", pub.Alg, DomainState, d)
			}
		}
		if Verify(pub, DomainState, body, sig[:len(sig)-1]) == nil || Verify(pub, DomainState, body, append(sig, 0)) == nil {
			t.Fatalf("%s: a truncated or extended signature verifies", pub.Alg)
		}
		for _, other := range testSigners(t) {
			if Verify(other.Public(), DomainState, body, sig) == nil {
				t.Fatalf("%s: another key verifies the signature", pub.Alg)
			}
		}
		for bit := range len(pub.Bytes) * 8 {
			altered := PublicKey{Alg: pub.Alg, Bytes: flip(pub.Bytes, bit)}
			if Verify(altered, DomainState, body, sig) == nil {
				t.Fatalf("%s: key with bit %d flipped verifies", pub.Alg, bit)
			}
		}
	}
}

// FuzzVerifyNeverAcceptsAlteredBodies signs a fuzzed body and requires any
// other body, domain or signature to fail.
func FuzzVerifyNeverAcceptsAlteredBodies(f *testing.F) {
	signers := testSigners(f)
	f.Add([]byte("body"), []byte("other"), uint16(3), false)
	f.Add([]byte{}, []byte{0}, uint16(0), true)
	f.Fuzz(func(t *testing.T, body, other []byte, bit uint16, p256 bool) {
		s := signers[0]
		if p256 {
			s = signers[1]
		}
		sig, err := s.Sign(DomainControl, body)
		if err != nil {
			t.Fatal(err)
		}
		pub := s.Public()
		if err := Verify(pub, DomainControl, body, sig); err != nil {
			t.Fatalf("own signature: %v", err)
		}
		if string(other) != string(body) && Verify(pub, DomainControl, other, sig) == nil {
			t.Fatalf("signature of %q verifies %q", body, other)
		}
		if Verify(pub, DomainState, body, sig) == nil {
			t.Fatal("a Control signature verifies as a State signature")
		}
		if Verify(pub, DomainControl, body, flip(sig, int(bit)%(len(sig)*8))) == nil {
			t.Fatal("a signature with a flipped bit verifies")
		}
		// Arbitrary bytes are never a valid signature of this body.
		if len(other) == len(sig) && string(other) != string(sig) && Verify(pub, DomainControl, body, other) == nil {
			t.Fatal("arbitrary bytes verify as a signature")
		}
	})
}

// TestDeviceIDIsInjective: a device ID names exactly one key, and the algorithm
// is part of it.
func TestDeviceIDIsInjective(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.SliceOfN(rapid.Byte(), 1, 40).Draw(t, "key a")
		b := rapid.SliceOfN(rapid.Byte(), 1, 40).Draw(t, "key b")
		algA := rapid.SampledFrom([]Algorithm{Ed25519, P256}).Draw(t, "alg a")
		algB := rapid.SampledFrom([]Algorithm{Ed25519, P256}).Draw(t, "alg b")
		ka, kb := PublicKey{Alg: algA, Bytes: a}, PublicKey{Alg: algB, Bytes: b}
		same := algA == algB && string(a) == string(b)
		if (ka.DeviceID() == kb.DeviceID()) != same {
			t.Fatalf("%v and %v: IDs equal %v, keys equal %v", ka, kb, ka.DeviceID() == kb.DeviceID(), same)
		}
		if err := ka.DeviceID().Validate(); err != nil {
			t.Fatalf("a derived ID is invalid: %v", err)
		}
	})
	// The separators keep (alg, key) pairs from colliding by concatenation.
	x := PublicKey{Alg: "ed", Bytes: []byte("25519k")}
	y := PublicKey{Alg: "ed25519", Bytes: []byte("k")}
	if x.DeviceID() == y.DeviceID() {
		t.Fatal("algorithm and key bytes collide when concatenated")
	}
	for _, s := range testSigners(t) {
		if s.Public().DeviceID() == testSigners(t)[0].Public().DeviceID() {
			t.Fatal("two generated keys share an ID")
		}
	}
}

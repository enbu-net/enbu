package signing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func signers(t *testing.T) map[string]Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewP256Signer(k)
	if err != nil {
		t.Fatal(err)
	}
	_, ek, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Signer{"p256": p, "ed25519": NewEd25519Signer(ek)}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for name, s := range signers(t) {
		t.Run(name, func(t *testing.T) {
			sig, err := s.Sign(DomainState, []byte("body"))
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(s.Public(), DomainState, []byte("body"), sig); err != nil {
				t.Fatal(err)
			}
			if Verify(s.Public(), DomainState, []byte("body2"), sig) == nil {
				t.Fatal("tampered body accepted")
			}
		})
	}
}

func TestVerifyRejectsOtherDomain(t *testing.T) {
	for name, s := range signers(t) {
		t.Run(name, func(t *testing.T) {
			sig, _ := s.Sign(DomainControl, []byte("body"))
			if Verify(s.Public(), DomainState, []byte("body"), sig) == nil {
				t.Fatal("signature accepted under a different domain")
			}
		})
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	ss := signers(t)
	sig, _ := ss["p256"].Sign(DomainState, []byte("b"))
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	o, _ := NewP256Signer(other)
	if Verify(o.Public(), DomainState, []byte("b"), sig) == nil {
		t.Fatal("accepted with another key")
	}
	if Verify(ss["ed25519"].Public(), DomainState, []byte("b"), sig) == nil {
		t.Fatal("accepted with another algorithm")
	}
}

func TestP256RejectsHighS(t *testing.T) {
	s := signers(t)["p256"]
	sig, _ := s.Sign(DomainState, []byte("b"))
	n := elliptic.P256().Params().N
	high := new(big.Int).Sub(n, new(big.Int).SetBytes(sig[32:]))
	malleated := append([]byte(nil), sig[:32]...)
	malleated = append(malleated, high.FillBytes(make([]byte, 32))...)
	err := Verify(s.Public(), DomainState, []byte("b"), malleated)
	if err == nil || !strings.Contains(err.Error(), "high-S") {
		t.Fatalf("high-S signature: %v", err)
	}
}

func TestP256SignatureFoldsHighS(t *testing.T) {
	n := elliptic.P256().Params().N
	r, s := big.NewInt(5), new(big.Int).Sub(n, big.NewInt(3))
	sig, err := P256Signature(r, s)
	if err != nil {
		t.Fatal(err)
	}
	if new(big.Int).SetBytes(sig[32:]).Cmp(big.NewInt(3)) != 0 {
		t.Fatal("s was not folded to low-S")
	}
}

func TestP256RejectsBadLengthAndKeys(t *testing.T) {
	s := signers(t)["p256"]
	if Verify(s.Public(), DomainState, []byte("b"), make([]byte, 70)) == nil {
		t.Fatal("DER-sized signature accepted")
	}
	bad := PublicKey{Alg: P256, Bytes: make([]byte, 33)}
	if bad.Validate() == nil {
		t.Fatal("invalid point accepted")
	}
	if (PublicKey{Alg: "rsa", Bytes: []byte{1}}).Validate() == nil {
		t.Fatal("unknown algorithm accepted")
	}
	if (PublicKey{Alg: Ed25519, Bytes: []byte{1}}).Validate() == nil {
		t.Fatal("short ed25519 key accepted")
	}
}

func TestDeviceIDIsDeterministicAndKeyBound(t *testing.T) {
	ss := signers(t)
	a, b := ss["p256"].Public(), ss["ed25519"].Public()
	again := PublicKey{Alg: a.Alg, Bytes: append([]byte(nil), a.Bytes...)}
	if again.DeviceID() != a.DeviceID() || a.DeviceID() == b.DeviceID() {
		t.Fatal("device id is not a function of the key")
	}
	// The id is the SHA-256 of the domain separator, algorithm and key.
	want := sha256.New()
	want.Write([]byte("enbu.device-id.v1\x00p256\x00"))
	want.Write(a.Bytes)
	if string(a.DeviceID()) != hex.EncodeToString(want.Sum(nil)) {
		t.Fatal("device id does not follow the specified derivation")
	}
	if len(a.DeviceID()) != 64 || a.DeviceID().Validate() != nil {
		t.Fatalf("unexpected device id %q", a.DeviceID())
	}
	// Same bytes under another algorithm label must not collide.
	if (PublicKey{Alg: Ed25519, Bytes: a.Bytes}).DeviceID() == a.DeviceID() {
		t.Fatal("algorithm is not part of the device id")
	}
}

func TestFingerprintFormat(t *testing.T) {
	id := DeviceID(strings.Repeat("ab", 32))
	if got := id.Fingerprint(); got != "abab-abab-abab-abab-abab" {
		t.Fatalf("fingerprint %q", got)
	}
	if DeviceID("zz").Validate() == nil || DeviceID(strings.Repeat("AB", 32)).Validate() == nil {
		t.Fatal("invalid device id accepted")
	}
}

func TestP256FromUncompressed(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := P256FromUncompressed(raw)
	if err != nil || pk.Validate() != nil || len(pk.Bytes) != 33 {
		t.Fatalf("conversion failed: %v", err)
	}
	if _, err := P256FromUncompressed(make([]byte, 65)); err == nil {
		t.Fatal("invalid point accepted")
	}
}

func TestP256SignatureRejectsValuesThatCannotBeASignature(t *testing.T) {
	n := elliptic.P256().Params().N
	one := big.NewInt(1)
	for name, rs := range map[string][2]*big.Int{
		"nil r":      {nil, one},
		"nil s":      {one, nil},
		"zero r":     {big.NewInt(0), one},
		"zero s":     {one, big.NewInt(0)},
		"negative r": {big.NewInt(-1), one},
		"r = N":      {new(big.Int).Set(n), one},
		"s = N":      {one, new(big.Int).Set(n)},
		"oversize s": {one, new(big.Int).Lsh(one, 300)},
	} {
		t.Run(name, func(t *testing.T) {
			if sig, err := P256Signature(rs[0], rs[1]); err == nil || sig != nil {
				t.Fatalf("accepted (%v, %v): %x %v", rs[0], rs[1], sig, err)
			}
		})
	}
}

func TestDomainWithTheSeparatorIsRejected(t *testing.T) {
	// ("a\x00b", "c") and ("a", "b\x00c") would otherwise sign the same bytes.
	for name, s := range signers(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := s.Sign("a\x00b", []byte("c")); !errors.Is(err, ErrInvalidDomain) {
				t.Fatalf("sign with a NUL domain: %v", err)
			}
			if _, err := s.Sign("", []byte("c")); !errors.Is(err, ErrInvalidDomain) {
				t.Fatalf("sign with an empty domain: %v", err)
			}
			sig, _ := s.Sign("a", []byte("b\x00c"))
			if err := Verify(s.Public(), "a\x00b", []byte("c"), sig); !errors.Is(err, ErrInvalidDomain) {
				t.Fatalf("verify with a NUL domain: %v", err)
			}
		})
	}
}

func TestEd25519RejectsBadSignatures(t *testing.T) {
	s := signers(t)["ed25519"]
	sig, _ := s.Sign(DomainState, []byte("body"))
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 1
	for name, bad := range map[string][]byte{"tampered": tampered, "short": sig[:63], "long": append(append([]byte(nil), sig...), 0), "empty": nil} {
		if err := Verify(s.Public(), DomainState, []byte("body"), bad); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("%s signature: %v", name, err)
		}
	}
}

func TestP256RejectsTamperedR(t *testing.T) {
	s := signers(t)["p256"]
	sig, _ := s.Sign(DomainState, []byte("body"))
	sig[0] ^= 1
	if err := Verify(s.Public(), DomainState, []byte("body"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered r: %v", err)
	}
}

func TestVerifyWithAnInvalidKeyReportsTheKey(t *testing.T) {
	sig := make([]byte, 64)
	for name, pk := range map[string]PublicKey{
		"unknown algorithm": {Alg: "rsa", Bytes: []byte{1}},
		"short p256":        {Alg: P256, Bytes: make([]byte, 32)},
		"bad prefix":        {Alg: P256, Bytes: append([]byte{5}, make([]byte, 32)...)},
		"short ed25519":     {Alg: Ed25519, Bytes: []byte{1}},
	} {
		if err := Verify(pk, DomainState, []byte("b"), sig); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestSignerConstructorsRejectBadKeys(t *testing.T) {
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewP256Signer(other); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("P-384 key: %v", err)
	}
	if _, err := NewP256Signer(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil key: %v", err)
	}
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	scalar, _ := b.Bytes()
	mismatched, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	mismatched.PublicKey = a.PublicKey // the public key of a different private key
	if _, err := NewP256Signer(mismatched); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("public key of another private key: %v", err)
	}
	short := NewEd25519Signer(ed25519.PrivateKey([]byte{1, 2, 3}))
	if _, err := short.Sign(DomainState, []byte("b")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short ed25519 key signed without error: %v", err)
	}
	if short.Public().Validate() == nil {
		t.Fatal("short ed25519 key produced a valid public key")
	}
}

func TestFingerprintOfAShortIDIsNotTruncated(t *testing.T) {
	if got := DeviceID("abcd").Fingerprint(); got != "abcd" {
		t.Fatalf("fingerprint = %q", got)
	}
}

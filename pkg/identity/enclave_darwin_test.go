//go:build darwin

package identity

import (
	"bytes"
	"crypto/mlkem"
	"os"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
)

func TestSecureEnclaveConstantsAreCached(t *testing.T) {
	a, err := loadSecurity()
	if err != nil {
		t.Fatal(err)
	}
	first := a.constant("kSecAttrTokenIDSecureEnclave")
	if first == 0 || a.constant("kSecAttrTokenIDSecureEnclave") != first {
		t.Fatal("constant lookup is not stable")
	}
	if _, ok := a.constants.Load("kSecAttrTokenIDSecureEnclave"); !ok {
		t.Fatal("constant was not cached")
	}
}

func TestSecureEnclaveRefusesMetadataWithoutKeyData(t *testing.T) {
	b := &enclaveBackend{}
	md := &Metadata{Version: 1, PublicInfo: PublicInfo{Backend: "secure-enclave", Algorithm: "P-256"}, Reference: "enbu.identity.v1.old"}
	if _, err := b.Load(md); err == nil {
		t.Fatal("loaded Keychain-reference metadata")
	}
	if _, err := b.LoadSigner(&SignerMetadata{Backend: "secure-enclave", Algorithm: "P-256", Reference: "enbu.signing.v1.old"}); err == nil {
		t.Fatal("loaded Keychain-reference signing metadata")
	}
	if _, err := b.UnsealSeed(md); err == nil {
		t.Fatal("unsealed without a sealed seed")
	}
}

func TestSecureEnclaveNativeLifecycle(t *testing.T) {
	if os.Getenv("ENBU_TEST_NATIVE_IDENTITY") != "1" {
		t.Skip("set ENBU_TEST_NATIVE_IDENTITY=1 on a Secure Enclave device")
	}
	b := &enclaveBackend{}
	if d := b.Probe(); !d.Available {
		t.Fatalf("native hardware unavailable: %+v", d)
	}
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	if len(md.EnclaveKey) == 0 || md.Reference != "" {
		t.Fatalf("metadata: %+v", md)
	}
	ct, err := age.EncryptForPublicKeys([]byte("native enclave"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	loaded, err := b.Load(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	out, err := age.Decrypt(ct, loaded)
	if err != nil || !bytes.Equal(out, []byte("native enclave")) {
		t.Fatalf("native decrypt: %q %v", out, err)
	}

	// A restore that yields another key must be refused, never used.
	_, other, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	swapped := *md
	swapped.EnclaveKey = other.EnclaveKey
	if _, err := b.Load(&swapped); err == nil {
		t.Fatal("loaded another key's data under this public key")
	}
	corrupt := *md
	corrupt.EnclaveKey = append([]byte(nil), md.EnclaveKey...)
	corrupt.EnclaveKey[len(corrupt.EnclaveKey)/2] ^= 1
	if _, err := b.Load(&corrupt); err == nil {
		t.Fatal("loaded corrupted key data")
	}

	seed := bytes.Repeat([]byte{3}, mlkem.SeedSize)
	if err := b.SealSeed(md, seed); err != nil {
		t.Fatal(err)
	}
	got, err := b.UnsealSeed(md)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("unseal: %x %v", got, err)
	}
	other.EnclaveSeal = md.EnclaveSeal
	if _, err := b.UnsealSeed(other); err == nil {
		t.Fatal("another Secure Enclave key unsealed the seed")
	}
}

func TestSecureEnclaveNativeSigner(t *testing.T) {
	if os.Getenv("ENBU_TEST_NATIVE_IDENTITY") != "1" {
		t.Skip("set ENBU_TEST_NATIVE_IDENTITY=1 on a Secure Enclave device")
	}
	b := &enclaveBackend{}
	s, md, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	md.PublicKey = s.Public()
	_ = s.Close()
	loaded, err := b.LoadSigner(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	if _, err := loaded.Sign("enbu-test", []byte("body")); err != nil {
		t.Fatal(err)
	}
}

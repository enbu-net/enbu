//go:build darwin

package identity

import (
	"os"
	"testing"
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
	if _, _, err := b.Load(&Metadata{Backend: "secure-enclave", Algorithm: algHardware}); err == nil {
		t.Fatal("loaded metadata without key data")
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
	m := &Manager{Dir: t.TempDir(), Mode: "hardware", Hardware: b}
	d, info, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, loaded, info.Recipient)
	_ = loaded.Close()

	// A restore that yields another key must be refused, never used.
	md, err := m.read("o/r")
	if err != nil {
		t.Fatal(err)
	}
	other := &Metadata{}
	key, s, err := b.Create(other)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Close()
	_ = s.Close()
	swapped := *md
	swapped.Enclave = &EnclaveKeys{ECDH: other.Enclave.ECDH, ECDHPublic: md.Enclave.ECDHPublic, Sign: md.Enclave.Sign}
	if _, _, err := b.Load(&swapped); err == nil {
		t.Fatal("loaded another key's data under this public key")
	}
	// Changed key data is not tested here: a real Secure Enclave ignores
	// some of its bytes (so a change there still restores this key, which
	// the public-key check accepts) and was seen to block on others.
}

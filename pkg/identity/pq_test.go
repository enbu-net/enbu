package identity

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/google/go-tpm/tpm2/transport"
)

func newHybridHardware(t *testing.T) (Identity, *softwareHardwareKey) {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &softwareHardwareKey{PrivateKey: k}
	seed := make([]byte, mlkem.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	id, err := NewHybridHardwareIdentity(h, seed)
	if err != nil {
		t.Fatal(err)
	}
	return id, h
}

func TestHybridHardwareIdentityUsesBothKeys(t *testing.T) {
	id, h := newHybridHardware(t)
	defer func() { _ = id.Close() }()
	if !strings.HasPrefix(id.Recipient().String(), "age1tagpq1") || !age.IsPostQuantum(id.Recipient().String()) {
		t.Fatalf("unexpected recipient %.24s", id.Recipient().String())
	}
	soft, err := agecrypto.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipients := []string{id.Recipient().String(), soft.Recipient().String()}
	if !age.PostQuantum(recipients) {
		t.Fatal("tagged and software hybrid recipients must form a post-quantum set")
	}
	ct, err := age.EncryptForPublicKeys([]byte("hybrid"), recipients)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ct), "-> mlkem768p256tag ") {
		t.Fatal("no tagged hybrid stanza")
	}
	for _, i := range []agecrypto.Identity{id, soft} {
		out, err := age.Decrypt(ct, i)
		if err != nil || string(out) != "hybrid" {
			t.Fatalf("decrypt: %q %v", out, err)
		}
	}
	if h.calls != 1 {
		t.Fatalf("hardware ECDH calls = %d, want 1", h.calls)
	}

	// A different ML-KEM key with the same hardware key must not decrypt:
	// the hardware half alone is not enough.
	seed := make([]byte, mlkem.SeedSize)
	_, _ = rand.Read(seed)
	sameDevice, err := NewHybridHardwareIdentity(h, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(ct, sameDevice); err == nil {
		t.Fatal("decrypted without the matching ML-KEM key")
	}
}

func TestHybridHardwareIdentityRejectsClassicalAndMalformedStanzas(t *testing.T) {
	id, h := newHybridHardware(t)
	classical, err := NewHardwareIdentity(h)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := age.EncryptForPublicKeys([]byte("classical"), []string{classical.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(ct, id); err == nil {
		t.Fatal("hybrid identity unwrapped a classical p256tag stanza")
	}
	if _, err := id.Unwrap([]*agecrypto.Stanza{{Type: "mlkem768p256tag"}}); err == nil || errors.Is(err, agecrypto.ErrIncorrectIdentity) {
		t.Fatalf("malformed stanza: %v", err)
	}
	short := []*agecrypto.Stanza{{Type: "mlkem768p256tag", Args: []string{"AAAAAA", "AAAA"}, Body: make([]byte, 32)}}
	if _, err := id.Unwrap(short); err == nil {
		t.Fatal("accepted a short encapsulated key")
	}
	if err := id.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := id.Unwrap(nil); err == nil {
		t.Fatal("used a closed identity")
	}
}

func TestHybridHardwareIdentityRequiresValidKeys(t *testing.T) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := NewHybridHardwareIdentity(&softwareHardwareKey{PrivateKey: k}, make([]byte, mlkem.SeedSize)); err == nil {
		t.Fatal("accepted a non-P-256 hardware key")
	}
	p, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := NewHybridHardwareIdentity(&softwareHardwareKey{PrivateKey: p}, make([]byte, 10)); err == nil {
		t.Fatal("accepted a short ML-KEM seed")
	}
}

// TestHybridIdentityOnTPM pairs a real (virtual) TPM ECDH key with ML-KEM.
func TestHybridIdentityOnTPM(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	classical, _, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, mlkem.SeedSize)
	_, _ = rand.Read(seed)
	id, err := NewHybridHardwareIdentity(classical.(*taggedIdentity).key, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	ct, err := age.EncryptForPublicKeys([]byte("TPM + ML-KEM"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(ct, id)
	if err != nil || string(out) != "TPM + ML-KEM" {
		t.Fatalf("decrypt: %q %v", out, err)
	}
}

func TestManagerCreatesPostQuantumKeyringIdentity(t *testing.T) {
	m := newManager(t)
	m.PostQuantum = true
	m.Hardware = &fakeHardware{available: true}
	id, info, warning, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if info.Backend != "keyring" || info.Algorithm != "MLKEM768-X25519" || !strings.HasPrefix(info.Recipient, "age1pq1") {
		t.Fatalf("info: %+v", info)
	}
	if !strings.Contains(warning, "hardware-bound hybrid keys are not supported yet") {
		t.Fatalf("warning: %q", warning)
	}
	if m.Hardware.(*fakeHardware).creates != 0 {
		t.Fatal("created a classical hardware key in post-quantum mode")
	}
	md, err := m.read("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(md.PublicKey), "SECRET") {
		t.Fatal("metadata holds the secret key")
	}

	// The saved identity loads without the flag: the metadata names it.
	m.PostQuantum = false
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	ct, err := age.EncryptForPublicKeys([]byte("pq"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := age.Decrypt(ct, loaded); err != nil || string(out) != "pq" {
		t.Fatalf("decrypt: %q %v", out, err)
	}

	// The keyring secret must be the algorithm the metadata names.
	md.Algorithm = "X25519"
	if err := saveMetadata(m.Path("o/r"), md); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("loaded a hybrid secret as X25519")
	}
}

func TestManagerPostQuantumHardwareModeFails(t *testing.T) {
	m := newManager(t)
	m.PostQuantum = true
	m.Mode = "hardware"
	if _, _, _, err := m.Create("o/r"); err == nil {
		t.Fatal("hardware mode created a keyring identity")
	}
}

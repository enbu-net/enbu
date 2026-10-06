package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/signing"
)

func TestSignerSoftwareFallbackAndReuse(t *testing.T) {
	m := newManager(t)
	s, info, warning, err := m.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if !info.Created || info.Backend != "keyring" || info.Algorithm != "Ed25519" || warning == "" {
		t.Fatalf("unexpected: %+v %q", info, warning)
	}
	if info.DeviceID != s.Public().DeviceID() {
		t.Fatal("device id does not match the signing key")
	}
	sig, err := s.Sign(signing.DomainState, []byte("x"))
	if err != nil || signing.Verify(s.Public(), signing.DomainState, []byte("x"), sig) != nil {
		t.Fatalf("sign/verify: %v", err)
	}
	again, info2, _, err := m.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	if info2.Created || info2.DeviceID != info.DeviceID {
		t.Fatalf("signer was not reused: %+v", info2)
	}
	if got, err := m.SignerInfo("ws"); err != nil || got.DeviceID != info.DeviceID {
		t.Fatalf("info: %+v %v", got, err)
	}
}

func TestSignerIsSeparateFromEncryptionIdentity(t *testing.T) {
	m := newManager(t)
	id, info, _, err := m.Create("ws")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	s, sinfo, _, err := m.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if m.SignerPath("ws") == m.Path("ws") {
		t.Fatal("signing and encryption metadata share a file")
	}
	if string(s.Public().Bytes) == info.Recipient || sinfo.Algorithm == info.Algorithm {
		t.Fatal("signing key must be a different keypair")
	}
}

func TestSignerRejectsTamperedMetadata(t *testing.T) {
	m := newManager(t)
	s, _, _, err := m.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	md, err := m.readSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	// Change the first character for certain; replacing it with a fixed one
	// would leave the id unchanged one time in sixteen.
	first := "0"
	if md.DeviceID[0] == '0' {
		first = "1"
	}
	md.DeviceID = signing.DeviceID(first + string(md.DeviceID)[1:])
	if err := saveJSON(m.SignerPath("ws"), md); err != nil {
		t.Fatal(err)
	}
	if _, err := m.LoadSigner("ws"); err == nil {
		t.Fatal("accepted a device id that does not match the key")
	}
}

func TestSignerHardwareModeRequiresBackend(t *testing.T) {
	m := newManager(t)
	m.Mode = "hardware"
	if _, _, _, err := m.CreateSigner("ws"); err == nil {
		t.Fatal("hardware mode fell back to software")
	}
	m.Mode = "keyring"
	s, info, _, err := m.CreateSigner("ws")
	if err != nil || info.Backend != "keyring" {
		t.Fatalf("keyring mode: %+v %v", info, err)
	}
	_ = s.Close()
}

type signerHardware struct {
	fakeHardware
	create func() (signing.Signer, *SignerMetadata, error)
	load   func(*SignerMetadata) (signing.Signer, error)
}

func (h *signerHardware) CreateSigner() (signing.Signer, *SignerMetadata, error) { return h.create() }

func (h *signerHardware) LoadSigner(md *SignerMetadata) (signing.Signer, error) {
	if h.load != nil {
		return h.load(md)
	}
	return nil, errors.New("not used")
}

func TestSignerHardwareCreateFailureDoesNotFallBack(t *testing.T) {
	m := newManager(t)
	m.Hardware = &signerHardware{fakeHardware: fakeHardware{available: true}, create: func() (signing.Signer, *SignerMetadata, error) {
		return nil, nil, errors.New("tpm broke")
	}}
	if _, _, _, err := m.CreateSigner("ws"); err == nil {
		t.Fatal("hardware failure silently fell back")
	}
}

func TestLoadSignerRejectsAKeyringSignerInHardwareMode(t *testing.T) {
	m := newManager(t)
	s, _, _, err := m.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	m.Mode = "hardware"
	if _, err := m.LoadSigner("ws"); err == nil {
		t.Fatal("a software signer satisfied hardware mode")
	}
}

func TestLoadSignerRejectsMissingOrMalformedSeed(t *testing.T) {
	for name, damage := range map[string]func(memoryVault, string){
		"missing":   func(v memoryVault, ref string) { delete(v, ref) },
		"malformed": func(v memoryVault, ref string) { v[ref] = []byte("not hex") },
		"short":     func(v memoryVault, ref string) { v[ref] = []byte("abcd") },
	} {
		t.Run(name, func(t *testing.T) {
			m := newManager(t)
			s, _, _, err := m.CreateSigner("ws")
			if err != nil {
				t.Fatal(err)
			}
			_ = s.Close()
			md, err := m.readSigner("ws")
			if err != nil {
				t.Fatal(err)
			}
			damage(m.Vault.(memoryVault), md.Reference)
			if _, err := m.LoadSigner("ws"); err == nil {
				t.Fatal("damaged keyring entry loaded")
			}
		})
	}
}

// A seed swapped in the keyring must not be accepted under the old device id.
func TestLoadSignerRejectsAKeyDifferentFromItsMetadata(t *testing.T) {
	m := newManager(t)
	first, _, _, err := m.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	other := newManager(t)
	second, _, _, err := other.CreateSigner("other")
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	mdFirst, _ := m.readSigner("ws")
	mdOther, _ := other.readSigner("other")
	m.Vault.(memoryVault)[mdFirst.Reference] = other.Vault.(memoryVault)[mdOther.Reference]
	if _, err := m.LoadSigner("ws"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("swapped seed: %v", err)
	}
}

func TestSignerHardwareCreateAndLoad(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	hw := &signerHardware{fakeHardware: fakeHardware{available: true}}
	hw.create = func() (signing.Signer, *SignerMetadata, error) {
		return signing.NewEd25519Signer(key), &SignerMetadata{Backend: "tpm", Algorithm: "P-256", Device: "test"}, nil
	}
	hw.load = func(*SignerMetadata) (signing.Signer, error) { return signing.NewEd25519Signer(key), nil }
	m := newManager(t)
	m.Hardware = hw
	s, info, warning, err := m.CreateSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if info.Backend != "tpm" || warning != "" || info.DeviceID != s.Public().DeviceID() {
		t.Fatalf("hardware create: %+v %q", info, warning)
	}
	again, err := m.LoadSigner("ws")
	if err != nil {
		t.Fatal(err)
	}
	_ = again.Close()
	if shown, err := m.SignerInfo("ws"); err != nil || shown.DeviceID != info.DeviceID {
		t.Fatalf("info: %+v %v", shown, err)
	}
}

func TestSignerHardwareRejectsInvalidMetadata(t *testing.T) {
	for name, md := range map[string]*SignerMetadata{
		"nil":            nil,
		"no backend":     {},
		"software label": {Backend: "keyring"},
	} {
		t.Run(name, func(t *testing.T) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			closed := &closeCounter{Signer: signing.NewEd25519Signer(key)}
			hw := &signerHardware{fakeHardware: fakeHardware{available: true}}
			hw.create = func() (signing.Signer, *SignerMetadata, error) { return closed, md, nil }
			m := newManager(t)
			m.Hardware = hw
			if _, _, _, err := m.CreateSigner("ws"); err == nil {
				t.Fatal("invalid hardware metadata was accepted")
			}
			if closed.n != 1 {
				t.Fatalf("signer closed %d times, want 1", closed.n)
			}
			if _, err := os.Stat(m.SignerPath("ws")); err == nil {
				t.Fatal("metadata was saved for an invalid signer")
			}
		})
	}
}

type closeCounter struct {
	signing.Signer
	n int
}

func (c *closeCounter) Close() error { c.n++; return nil }

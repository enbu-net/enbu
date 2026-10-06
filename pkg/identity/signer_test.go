package identity

import (
	"errors"
	"testing"

	vtpm "github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2/transport"
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
	md.DeviceID = signing.DeviceID("00" + string(md.DeviceID)[2:])
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

func TestTPMSignerRoundTripAndRestart(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	s, md, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	md.PublicKey = s.Public()
	sig, err := s.Sign(signing.DomainControl, []byte("control"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Verify(s.Public(), signing.DomainControl, []byte("control"), sig); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := v.Snapshot()
	v = vtpm.New()
	if err := v.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	s2, err := b.LoadSigner(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if s2.Public().DeviceID() != s.Public().DeviceID() {
		t.Fatal("reloaded key changed")
	}
	if _, err := s2.Sign(signing.DomainState, []byte("again")); err != nil {
		t.Fatal(err)
	}
	bad := *md
	bad.TPMName = []byte("bad")
	if _, err := b.LoadSigner(&bad); err == nil {
		t.Fatal("accepted corrupt Name")
	}
}

func TestTPMSignerRejectsEncryptionKey(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	_, err = b.LoadSigner(&SignerMetadata{Backend: "tpm", Algorithm: "P-256", TPMPublic: md.TPMPublic, TPMPrivate: md.TPMPrivate, TPMName: md.TPMName})
	if err == nil {
		t.Fatal("ECDH identity key loaded as a signer")
	}
}

type signerHardware struct {
	fakeHardware
	create func() (signing.Signer, *SignerMetadata, error)
}

func (h *signerHardware) CreateSigner() (signing.Signer, *SignerMetadata, error) { return h.create() }
func (h *signerHardware) LoadSigner(*SignerMetadata) (signing.Signer, error) {
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

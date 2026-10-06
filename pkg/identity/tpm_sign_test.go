package identity

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	vtpm "github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2/transport"
)

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

func TestTPMSignerLoadChecksItsMetadata(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	s, md, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	for name, damage := range map[string]func(*SignerMetadata){
		"other backend":   func(m *SignerMetadata) { m.Backend = "secure-enclave" },
		"other algorithm": func(m *SignerMetadata) { m.Algorithm = "Ed25519" },
		"tampered public": func(m *SignerMetadata) {
			m.TPMPublic = append([]byte(nil), m.TPMPublic...)
			m.TPMPublic[len(m.TPMPublic)-1] ^= 1
		},
		"tampered private": func(m *SignerMetadata) {
			m.TPMPrivate = append([]byte(nil), m.TPMPrivate...)
			m.TPMPrivate[len(m.TPMPrivate)-1] ^= 1
		},
		"tampered name": func(m *SignerMetadata) { m.TPMName = []byte("bad") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *md
			damage(&bad)
			if loaded, err := b.LoadSigner(&bad); err == nil {
				_ = loaded.Close()
				t.Fatal("damaged metadata loaded")
			}
		})
	}
}

func TestTPMSignerSignaturesAreLowSAndStopAfterClose(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	s, _, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	for i := 0; i < 8; i++ {
		sig, err := s.Sign(signing.DomainState, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if new(big.Int).SetBytes(sig[32:]).Cmp(half) > 0 {
			t.Fatalf("signature %d is not low-S", i)
		}
	}
	if _, err := s.Sign("bad\x00domain", []byte("b")); err == nil {
		t.Fatal("a domain with the separator byte was signed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(signing.DomainState, []byte("b")); err == nil {
		t.Fatal("a closed signer signed")
	}
}

// The ECDH identity key is a different key, so a signer reference must not load as one.
func TestTPMIdentityKeyIsNotLoadedAsSigner(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	s, md, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	asIdentity := &Metadata{Version: 1, PublicInfo: PublicInfo{Backend: "tpm", Algorithm: "P-256"},
		TPMPublic: md.TPMPublic, TPMPrivate: md.TPMPrivate, TPMName: md.TPMName}
	if id, err := b.Load(asIdentity); err == nil {
		_ = id.Close()
		t.Fatal("a signing key loaded as the encryption identity")
	}
}

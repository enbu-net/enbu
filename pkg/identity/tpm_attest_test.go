//go:build linux && cgo

package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// testTPMMaker is a TPM maker's CA for the simulator's EK.
type testTPMMaker struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestTPMMaker(t *testing.T) *testTPMMaker {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"Test TPM Maker"}, CommonName: "Test EK Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testTPMMaker{key: key, cert: cert}
}

func (m *testTPMMaker) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(m.cert)
	return p
}

// issue returns an EK certificate for pub shaped like real ones: an empty
// subject and a critical subject alternative name holding the TPM's maker,
// model and version as a directory name.
func (m *testTPMMaker) issue(t *testing.T, pub any) []byte {
	t.Helper()
	tpmAttrs := pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: "id:414D4400"},
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 2}, Value: "TEST"},
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 3}, Value: "id:00010002"},
	}}
	name, err := asn1.Marshal(tpmAttrs.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name}})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Critical: true, Value: san}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.cert, pub, m.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// provisionEK writes an EK certificate into the simulator's NV, as a TPM
// maker does at manufacture.
func provisionEK(t *testing.T, tpm transport.TPM, cert []byte) {
	t.Helper()
	platform := tpm2.AuthHandle{Handle: tpm2.TPMRHPlatform, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}
	public := tpm2.TPMSNVPublic{NVIndex: ekCertIndexECC, NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{PPWrite: true, PPRead: true, OwnerRead: true, AuthRead: true, NoDA: true, PlatformCreate: true, NT: tpm2.TPMNTOrdinary},
		DataSize:   uint16(len(cert))}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: platform, PublicInfo: tpm2.New2B(public)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	name, err := tpm2.NVName(&public)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(cert); off += 512 {
		end := min(off+512, len(cert))
		if _, err := (tpm2.NVWrite{AuthHandle: platform, NVIndex: tpm2.NamedHandle{Handle: ekCertIndexECC, Name: *name},
			Data: tpm2.TPM2BMaxNVBuffer{Buffer: cert[off:end]}, Offset: uint16(off)}).Execute(tpm); err != nil {
			t.Fatal(err)
		}
	}
}

func simulatorEK(t *testing.T, tpm transport.TPM) *ecdsa.PublicKey {
	t.Helper()
	ek, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		InPublic: tpm2.New2B(tpm2.ECCEKTemplate)}).Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = flush(tpm, ek.ObjectHandle) }()
	public, err := ek.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ecdsaPublic(public)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// TestTPMAttestation runs the whole attestation on the reference simulator:
// keys certified at creation, the evidence verified up to the maker's root,
// and the challenge answered only by the TPM that holds the EK.
func TestTPMAttestation(t *testing.T) {
	sim, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sim.Close() }()
	tpm := transport.FromReadWriter(sim)
	maker := newTestTPMMaker(t)
	b := &TPMBackend{Device: "simulator", Open: func() (transport.TPMCloser, error) { return &recordingTPM{inner: tpm}, nil }}

	if _, err := b.Evidence(CertifiedKey{}); err != ErrNoEKCertificate {
		t.Fatalf("evidence without an EK certificate: %v", err)
	}
	provisionEK(t, tpm, maker.issue(t, simulatorEK(t, tpm)))

	// The simulator holds three objects, so each key is closed before the
	// next is created; a real TPM's resource manager swaps them.
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	s, smd, err := b.CreateSigner()
	if err != nil {
		t.Fatal(err)
	}
	signer := s.Public()
	_ = s.Close()
	if md.TPMCertified == nil || smd.TPMCertified == nil {
		t.Fatal("the TPM did not certify the new keys")
	}

	ev, err := b.Evidence(*md.TPMCertified, *smd.TPMCertified)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	att, err := VerifyEvidence(ev, maker.roots(), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if att.Maker != "Test TPM Maker" || len(att.Keys) != 2 {
		t.Fatalf("attestation: %+v", att)
	}
	if att.Keys[0].Signing || !bytes.Equal(must(att.Keys[0].Key.Bytes()), md.PublicKey) {
		t.Fatal("the attested ECDH key is not the identity's")
	}
	if !att.Keys[1].Signing || !bytes.Equal(must(signing.P256FromUncompressed(must(att.Keys[1].Key.Bytes()))).Bytes, signer.Bytes) {
		t.Fatal("the attested signing key is not the signer's")
	}
	secret, blob, encrypted, err := att.Challenge(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Activate(blob, encrypted)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("activate: %x %v", got, err)
	}

	t.Run("unknown maker", func(t *testing.T) {
		if _, err := VerifyEvidence(ev, newTestTPMMaker(t).roots(), nil, now); err == nil {
			t.Fatal("an EK certificate from an unknown maker was accepted")
		}
	})
	t.Run("copied EK certificate", func(t *testing.T) {
		// A genuine certificate of another TPM passes the chain check, but
		// the challenge is then encrypted to an EK this TPM does not hold.
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		forged := *ev
		forged.EKCertificates = [][]byte{maker.issue(t, other.Public())}
		att, err := VerifyEvidence(&forged, maker.roots(), nil, now)
		if err != nil {
			t.Fatal(err)
		}
		_, blob, encrypted, err := att.Challenge(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Activate(blob, encrypted); err == nil {
			t.Fatal("a TPM answered a challenge for another TPM's EK")
		}
	})
	t.Run("tampered evidence", func(t *testing.T) {
		attest := *md.TPMCertified
		attest.Attest = bytes.Clone(attest.Attest)
		attest.Attest[len(attest.Attest)-1] ^= 1
		swapped := *md.TPMCertified
		swapped.Public = smd.TPMCertified.Public
		otherAK := *ev
		otherAK.AKPublic = smd.TPMCertified.Public
		for name, e := range map[string]*TPMEvidence{
			"attest":    {EKCertificates: ev.EKCertificates, AKPublic: ev.AKPublic, Keys: []CertifiedKey{attest}},
			"other key": {EKCertificates: ev.EKCertificates, AKPublic: ev.AKPublic, Keys: []CertifiedKey{swapped}},
			"other AK":  &otherAK,
			"no keys":   {EKCertificates: ev.EKCertificates, AKPublic: ev.AKPublic},
		} {
			if _, err := VerifyEvidence(e, maker.roots(), nil, now); err == nil {
				t.Errorf("%s: tampered evidence was accepted", name)
			}
		}
	})
}

func must[T any](b T, err error) T {
	if err != nil {
		panic(err)
	}
	return b
}

package identity

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// signTemplate is a non-restricted ECDSA P-256 signing-only key. It cannot
// decrypt, so it can never serve as the encryption identity.
func signTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, SignEncrypt: true, Decrypt: false},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA, Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
			CurveID:   tpm2.TPMECCNistP256, KDF: tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

func (b *TPMBackend) CreateSigner() (signing.Signer, *SignerMetadata, error) {
	t, parent, err := b.primary()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = t.Close() }()
	defer func() {
		if parent.ObjectHandle != 0 {
			_ = flush(t, parent.ObjectHandle)
		}
	}()
	created, err := (tpm2.Create{ParentHandle: tpm2.AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}, InPublic: tpm2.New2B(signTemplate())}).Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("creating TPM signing child: %w", err)
	}
	pub, err := created.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return nil, nil, err
	}
	md := &SignerMetadata{Backend: "tpm", Algorithm: "P-256", Device: b.Device,
		TPMPublic: tpm2.Marshal(created.OutPublic), TPMPrivate: tpm2.Marshal(created.OutPrivate), TPMName: name.Buffer}
	if err := flush(t, parent.ObjectHandle); err != nil {
		return nil, nil, err
	}
	parent.ObjectHandle = 0
	s, err := b.LoadSigner(md)
	if err != nil {
		return nil, nil, err
	}
	return s, md, nil
}

func (b *TPMBackend) LoadSigner(md *SignerMetadata) (signing.Signer, error) {
	if md.Backend != "tpm" || md.Algorithm != "P-256" {
		return nil, errors.New("invalid TPM signing metadata")
	}
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](md.TPMPublic)
	if err != nil {
		return nil, fmt.Errorf("TPM public blob: %w", err)
	}
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](md.TPMPrivate)
	if err != nil {
		return nil, fmt.Errorf("TPM private blob: %w", err)
	}
	pub, err := public.Contents()
	if err != nil {
		return nil, err
	}
	// Compare every attribute, scheme and curve so a swapped-in key (for example
	// the ECDH identity key) cannot be loaded as a signer.
	expected := signTemplate()
	expected.Unique = pub.Unique
	if !bytes.Equal(tpm2.Marshal(expected), tpm2.Marshal(*pub)) {
		return nil, errors.New("TPM key does not match signing-only template")
	}
	// md.TPMName is unauthenticated metadata. This check catches edits to the
	// public blob; the TPM's own Load, which verifies the private blob against
	// the parent seed, is what really guards the key, and its Name is compared
	// again below.
	name, err := tpm2.ObjectName(pub)
	if err != nil || !bytes.Equal(name.Buffer, md.TPMName) {
		return nil, errors.New("TPM object Name mismatch")
	}
	parms, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	point, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	ecdhPub, err := tpm2.ECDHPub(parms, point)
	if err != nil {
		return nil, err
	}
	pk, err := signing.P256FromUncompressed(ecdhPub.Bytes())
	if err != nil {
		return nil, err
	}
	t, parent, err := b.primary()
	if err != nil {
		return nil, err
	}
	loaded, err := (tpm2.Load{ParentHandle: tpm2.AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}, InPublic: *public, InPrivate: *private}).Execute(t)
	if err != nil {
		_ = flush(t, parent.ObjectHandle)
		_ = t.Close()
		return nil, fmt.Errorf("loading TPM signing child blob: %w", err)
	}
	s := &tpmSigner{t: t, handle: loaded.ObjectHandle, name: loaded.Name, pk: pk, parent: parent.ObjectHandle}
	if !bytes.Equal(loaded.Name.Buffer, md.TPMName) {
		_ = s.Close()
		return nil, errors.New("loaded TPM object Name mismatch")
	}
	return s, nil
}

type tpmSigner struct {
	mu     sync.Mutex
	t      transport.TPMCloser
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pk     signing.PublicKey
	parent tpm2.TPMHandle
	closed bool
}

func (s *tpmSigner) Public() signing.PublicKey { return s.pk }

func (s *tpmSigner) Sign(domain string, body []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("TPM signing key is closed")
	}
	if err := signing.ValidateDomain(domain); err != nil {
		return nil, err
	}
	rsp, err := (tpm2.Sign{
		KeyHandle:  tpm2.AuthHandle{Handle: s.handle, Name: s.name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		Digest:     tpm2.TPM2BDigest{Buffer: signing.P256Digest(domain, body)},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}).Execute(s.t)
	if err != nil {
		return nil, fmt.Errorf("TPM sign: %w", err)
	}
	sig, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
	}
	if len(sig.SignatureR.Buffer) > 32 || len(sig.SignatureS.Buffer) > 32 {
		return nil, errors.New("invalid TPM signature")
	}
	out, err := signing.P256Signature(new(big.Int).SetBytes(sig.SignatureR.Buffer), new(big.Int).SetBytes(sig.SignatureS.Buffer))
	if err != nil {
		return nil, fmt.Errorf("TPM signature: %w", err)
	}
	if err := signing.Verify(s.pk, domain, body, out); err != nil {
		return nil, fmt.Errorf("TPM produced an invalid signature: %w", err)
	}
	return out, nil
}

func (s *tpmSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(flush(s.t, s.handle), flush(s.t, s.parent), s.t.Close())
}

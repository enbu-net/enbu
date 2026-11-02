package identity

// TPM attestation lets an admin check, before approving a device, that the
// device's keys were created inside a genuine TPM and cannot leave it.
//
// When a key is created, TPM2_CertifyCreation has the device's attestation key
// (AK) sign the new key's Name. The AK is a restricted signing primary in the
// endorsement hierarchy, so the TPM derives the same AK every time, and a
// restricted key only signs data the TPM produced itself. A signature over a
// Name therefore proves that this TPM created the key, and the Name, a hash of
// the public area, covers fixedTPM and every other attribute.
//
// A signature by some AK alone proves nothing about the TPM that made it: the
// endorsement key (EK) certificate a TPM maker issues is public and can be
// copied to any request. The verifier therefore encrypts a challenge to the
// certified EK, bound to the AK's Name (TPM2_MakeCredential), and only the TPM
// that holds both that EK and that AK can recover it
// (TPM2_ActivateCredential).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// The NV indices of the EK certificates (TCG EK Credential Profile, low range)
// and the persistent handles Windows and tpm2-tools keep the EKs at.
const (
	ekCertIndexRSA = tpm2.TPMHandle(0x01C00002)
	ekCertIndexECC = tpm2.TPMHandle(0x01C0000A)
	ekHandleRSA    = tpm2.TPMHandle(0x81010001)
	ekHandleECC    = tpm2.TPMHandle(0x81010002)
)

// CertifiedKey is a TPM's signed statement that it created a key.
type CertifiedKey struct {
	Public    []byte `json:"public"`    // TPM2B_PUBLIC of the key
	Attest    []byte `json:"attest"`    // TPM2B_ATTEST from TPM2_CertifyCreation
	Signature []byte `json:"signature"` // TPMT_SIGNATURE of Attest by the AK
}

// TPMEvidence is what a device hands an admin to have its keys attested.
type TPMEvidence struct {
	// EKCertificates holds the EK certificate (DER) first, then any
	// intermediate CA certificates the device found.
	EKCertificates [][]byte       `json:"ek_certificates"`
	AKPublic       []byte         `json:"ak_public"` // TPM2B_PUBLIC
	Keys           []CertifiedKey `json:"keys"`
}

// ErrNoEKCertificate means the TPM holds no EK certificate, so its keys
// cannot be attested.
var ErrNoEKCertificate = errors.New("the TPM has no endorsement key certificate")

// akTemplate is the attestation key: a restricted ECDSA P-256 signing key.
func akTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, Restricted: true, SignEncrypt: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA, Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
			CurveID:   tpm2.TPMECCNistP256, KDF: tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}
}

// matchesTemplate reports whether public is template apart from its key.
func matchesTemplate(public *tpm2.TPMTPublic, template tpm2.TPMTPublic) bool {
	template.Unique = public.Unique
	return bytes.Equal(tpm2.Marshal(template), tpm2.Marshal(*public))
}

// createAK derives the attestation key. The caller holds c.mu and flushes it.
func createAK(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	ak, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		InPublic: tpm2.New2B(akTemplate())}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("creating TPM attestation key: %w", err)
	}
	public, err := ak.OutPublic.Contents()
	if err == nil && !matchesTemplate(public, akTemplate()) {
		err = errors.New("TPM attestation key does not match its template")
	}
	if err == nil {
		var name *tpm2.TPM2BName
		name, err = tpm2.ObjectName(public)
		if err == nil && !bytes.Equal(name.Buffer, ak.Name.Buffer) {
			err = errors.New("TPM attestation key Name does not match its public area")
		}
	}
	if err != nil {
		_ = flush(t, ak.ObjectHandle)
		return nil, err
	}
	return ak, nil
}

// certifyCreated has the AK certify a key Create just returned. It returns
// nil when the TPM cannot attest: the key works all the same, it is only
// reported as unattested. The caller holds c.mu.
func (c *tpmConn) certifyCreated(created *tpm2.CreateResponse) *CertifiedKey {
	loaded, err := (tpm2.Load{ParentHandle: c.parentAuth(), InPublic: created.OutPublic, InPrivate: created.OutPrivate}).Execute(c.t)
	if err != nil {
		return nil
	}
	defer func() { _ = flush(c.t, loaded.ObjectHandle) }()
	ak, err := createAK(c.t)
	if err != nil {
		return nil
	}
	defer func() { _ = flush(c.t, ak.ObjectHandle) }()
	rsp, err := (tpm2.CertifyCreation{
		SignHandle:     tpm2.AuthHandle{Handle: ak.ObjectHandle, Name: ak.Name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		ObjectHandle:   tpm2.NamedHandle{Handle: loaded.ObjectHandle, Name: loaded.Name},
		CreationHash:   created.CreationHash,
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		CreationTicket: created.CreationTicket,
	}).Execute(c.t)
	if err != nil {
		return nil
	}
	return &CertifiedKey{Public: tpm2.Marshal(created.OutPublic), Attest: tpm2.Marshal(rsp.CertifyInfo), Signature: tpm2.Marshal(rsp.Signature)}
}

// Evidence collects what an admin needs to attest the given keys: the EK
// certificate and the AK. It returns ErrNoEKCertificate when the TPM holds
// none.
func (b *TPMBackend) Evidence(keys ...CertifiedKey) (*TPMEvidence, error) {
	if len(keys) == 0 {
		return nil, errors.New("no certified TPM keys to attest")
	}
	c, err := b.acquire()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.release(c) }()
	c.mu.Lock()
	defer c.mu.Unlock()
	cert, err := readEKCertificate(c.t)
	if err != nil {
		return nil, err
	}
	ak, err := createAK(c.t)
	if err != nil {
		return nil, err
	}
	_ = flush(c.t, ak.ObjectHandle)
	return &TPMEvidence{EKCertificates: [][]byte{cert}, AKPublic: tpm2.Marshal(ak.OutPublic), Keys: keys}, nil
}

// readEKCertificate returns the TPM's EK certificate, preferring the ECC one.
// It returns ErrNoEKCertificate only when neither index is defined, so a
// failed read is not mistaken for a TPM without a certificate.
func readEKCertificate(t transport.TPM) ([]byte, error) {
	var errs []error
	for _, index := range []tpm2.TPMHandle{ekCertIndexECC, ekCertIndexRSA} {
		cert, err := readNV(t, index)
		if err == nil {
			return cert, nil
		}
		errs = append(errs, err)
	}
	if errors.Is(errs[0], tpm2.TPMRCHandle) && errors.Is(errs[1], tpm2.TPMRCHandle) {
		return nil, ErrNoEKCertificate
	}
	return nil, fmt.Errorf("reading the TPM's EK certificate: %w", errors.Join(errs...))
}

// readNV reads a whole NV index, authorizing with the index itself (EK
// certificates are AUTHREAD with an empty authValue) or else the owner.
func readNV(t transport.TPM, index tpm2.TPMHandle) ([]byte, error) {
	pub, err := (tpm2.NVReadPublic{NVIndex: index}).Execute(t)
	if err != nil {
		return nil, err
	}
	contents, err := pub.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	nv := tpm2.NamedHandle{Handle: index, Name: pub.NVName}
	auths := []tpm2.AuthHandle{
		{Handle: index, Name: pub.NVName, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		{Handle: tpm2.TPMRHOwner, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
	}
	var errs []error
	for _, auth := range auths {
		data, err := readNVWith(t, auth, nv, contents.DataSize)
		if err == nil {
			return data, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func readNVWith(t transport.TPM, auth tpm2.AuthHandle, nv tpm2.NamedHandle, size uint16) ([]byte, error) {
	const chunk = 512 // below every TPM's MAX_NV_BUFFER_SIZE
	out := make([]byte, 0, size)
	for off := uint16(0); off < size; {
		n := min(chunk, size-off)
		rsp, err := (tpm2.NVRead{AuthHandle: auth, NVIndex: nv, Size: n, Offset: off}).Execute(t)
		if err != nil {
			return nil, err
		}
		if len(rsp.Data.Buffer) == 0 {
			return nil, errors.New("TPM returned an empty NV read")
		}
		out = append(out, rsp.Data.Buffer...)
		off += uint16(len(rsp.Data.Buffer))
	}
	return out, nil
}

// Activate answers an admin's challenge. The TPM recovers the secret only if
// it holds both the EK the challenge was encrypted to and the AK it names.
func (b *TPMBackend) Activate(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	c, err := b.acquire()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.release(c) }()
	c.mu.Lock()
	defer c.mu.Unlock()
	cert, err := readEKCertificate(c.t)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("EK certificate: %w", err)
	}
	want, err := ekFromCertificate(leaf)
	if err != nil {
		return nil, err
	}
	ek, flushEK, err := loadEK(c.t, want)
	if err != nil {
		return nil, err
	}
	defer flushEK()
	ak, err := createAK(c.t)
	if err != nil {
		return nil, err
	}
	defer func() { _ = flush(c.t, ak.ObjectHandle) }()
	// The EK's policy asks for the endorsement hierarchy's (empty) authValue.
	policy, closeSession, err := tpm2.PolicySession(c.t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeSession() }()
	if _, err := (tpm2.PolicySecret{AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		PolicySession: policy.Handle(), NonceTPM: policy.NonceTPM()}).Execute(c.t); err != nil {
		return nil, err
	}
	rsp, err := (tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{Handle: ak.ObjectHandle, Name: ak.Name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		KeyHandle:      tpm2.AuthHandle{Handle: ek.handle, Name: ek.name, Auth: policy},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: credentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encryptedSecret},
	}).Execute(c.t)
	if err != nil {
		return nil, fmt.Errorf("answering the TPM attestation challenge: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}

type ekHandle struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
}

// loadEK returns the EK of the certificate (want), from its persistent handle
// when that holds it (an RSA EK takes seconds to derive), else derived anew.
func loadEK(t transport.TPM, want tpm2.TPMTPublic) (ekHandle, func(), error) {
	template, persistent := tpm2.ECCEKTemplate, ekHandleECC
	if want.Type == tpm2.TPMAlgRSA {
		template, persistent = tpm2.RSAEKTemplate, ekHandleRSA
	}
	wanted := tpm2.Marshal(want)
	if rsp, err := (tpm2.ReadPublic{ObjectHandle: persistent}).Execute(t); err == nil {
		if public, err := rsp.OutPublic.Contents(); err == nil && bytes.Equal(tpm2.Marshal(*public), wanted) {
			return ekHandle{handle: persistent, name: rsp.Name}, func() {}, nil
		}
	}
	ek, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
		InPublic: tpm2.New2B(template)}).Execute(t)
	if err != nil {
		return ekHandle{}, nil, fmt.Errorf("creating TPM endorsement key: %w", err)
	}
	if public, err := ek.OutPublic.Contents(); err != nil || !bytes.Equal(tpm2.Marshal(*public), wanted) {
		_ = flush(t, ek.ObjectHandle)
		return ekHandle{}, nil, errors.New("the TPM's endorsement key does not match its EK certificate")
	}
	return ekHandle{handle: ek.ObjectHandle, name: ek.Name}, func() { _ = flush(t, ek.ObjectHandle) }, nil
}

// AttestedKey is a key a verified TPM created.
type AttestedKey struct {
	Key *ecdsa.PublicKey
	// Signing tells the signing key from the ECDH (encryption) key.
	Signing bool
}

// Attestation is what VerifyEvidence established: the keys a TPM made by a
// known maker created, pending the challenge that proves the AK is in it.
type Attestation struct {
	Keys []AttestedKey
	// Maker names the EK certificate's issuer, for display.
	Maker  string
	ek     tpm2.TPMTPublic
	akName []byte
}

// VerifyEvidence checks the EK certificate chain up to roots, the AK, and
// every certified key. It does not prove that the AK lives in the EK's TPM:
// only a challenge (Attestation.Challenge) answered by the device does.
func VerifyEvidence(e *TPMEvidence, roots, intermediates *x509.CertPool, now time.Time) (*Attestation, error) {
	if e == nil || len(e.EKCertificates) == 0 {
		return nil, errors.New("TPM evidence is incomplete")
	}
	leaf, err := verifyEKChain(e.EKCertificates, roots, intermediates, now)
	if err != nil {
		return nil, err
	}
	return attestKeys(e, leaf)
}

// attestKeys checks the AK and the certified keys of evidence whose EK
// certificate leaf was verified.
func attestKeys(e *TPMEvidence, leaf *x509.Certificate) (*Attestation, error) {
	if len(e.Keys) == 0 {
		return nil, errors.New("TPM evidence certifies no key")
	}
	ek, err := ekFromCertificate(leaf)
	if err != nil {
		return nil, err
	}
	ak2B, err := tpm2.Unmarshal[tpm2.TPM2BPublic](e.AKPublic)
	if err != nil {
		return nil, fmt.Errorf("TPM attestation key: %w", err)
	}
	ak, err := ak2B.Contents()
	if err != nil {
		return nil, err
	}
	if !matchesTemplate(ak, akTemplate()) {
		return nil, errors.New("TPM attestation key is not a restricted signing key")
	}
	akName, err := tpm2.ObjectName(ak)
	if err != nil {
		return nil, err
	}
	akKey, err := ecdsaPublic(ak)
	if err != nil {
		return nil, err
	}
	maker := leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		maker = leaf.Issuer.Organization[0]
	}
	a := &Attestation{Maker: maker, ek: ek, akName: akName.Buffer}
	for _, k := range e.Keys {
		key, err := verifyCertifiedKey(k, akKey)
		if err != nil {
			return nil, err
		}
		a.Keys = append(a.Keys, key)
	}
	return a, nil
}

func verifyCertifiedKey(k CertifiedKey, ak *ecdsa.PublicKey) (AttestedKey, error) {
	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](k.Signature)
	if err != nil {
		return AttestedKey{}, fmt.Errorf("TPM attestation signature: %w", err)
	}
	ecc, err := sig.Signature.ECDSA()
	if err != nil || sig.SigAlg != tpm2.TPMAlgECDSA || ecc.Hash != tpm2.TPMAlgSHA256 {
		return AttestedKey{}, errors.New("TPM attestation signature is not ECDSA-SHA256")
	}
	attest2B, err := tpm2.Unmarshal[tpm2.TPM2BAttest](k.Attest)
	if err != nil {
		return AttestedKey{}, fmt.Errorf("TPM attestation: %w", err)
	}
	digest := sha256.Sum256(attest2B.Bytes())
	if !ecdsa.Verify(ak, digest[:], new(big.Int).SetBytes(ecc.SignatureR.Buffer), new(big.Int).SetBytes(ecc.SignatureS.Buffer)) {
		return AttestedKey{}, errors.New("TPM attestation signature does not verify")
	}
	attest, err := attest2B.Contents()
	if err != nil {
		return AttestedKey{}, err
	}
	if attest.Magic != tpm2.TPMGeneratedValue || attest.Type != tpm2.TPMSTAttestCreation {
		return AttestedKey{}, errors.New("TPM attestation is not a creation certificate")
	}
	creation, err := attest.Attested.Creation()
	if err != nil {
		return AttestedKey{}, err
	}
	public2B, err := tpm2.Unmarshal[tpm2.TPM2BPublic](k.Public)
	if err != nil {
		return AttestedKey{}, fmt.Errorf("certified TPM key: %w", err)
	}
	public, err := public2B.Contents()
	if err != nil {
		return AttestedKey{}, err
	}
	name, err := tpm2.ObjectName(public)
	if err != nil || !bytes.Equal(name.Buffer, creation.ObjectName.Buffer) {
		return AttestedKey{}, errors.New("TPM attestation certifies another key")
	}
	// Only enbu's own templates count: they fix the key in the TPM, and the
	// ECDH key can only run ECDH_ZGen under its policy.
	ecdhT, err := ecdhTemplate()
	if err != nil {
		return AttestedKey{}, err
	}
	var key AttestedKey
	switch {
	case matchesTemplate(public, ecdhT):
	case matchesTemplate(public, signTemplate()):
		key.Signing = true
	default:
		return AttestedKey{}, errors.New("certified TPM key does not match an enbu key template")
	}
	pk, err := ecdsaPublic(public)
	if err != nil {
		return AttestedKey{}, err
	}
	key.Key = pk
	return key, nil
}

func ecdsaPublic(public *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	parms, err := public.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}
	point, err := public.Unique.ECC()
	if err != nil {
		return nil, err
	}
	pk, err := tpm2.ECDHPub(parms, point)
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pk.Bytes())
}

// oidSubjectAltName is marked critical in EK certificates, whose subject is
// empty, and holds the TPM maker's attributes as a directory name, which
// crypto/x509 leaves unhandled.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// oidEKCertificate is tcg-kp-EKCertificate.
var oidEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

// verifyEKChain verifies the EK certificate chain and returns its leaf.
func verifyEKChain(chain [][]byte, roots, intermediates *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("EK certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if intermediates != nil {
		pool = intermediates.Clone()
	}
	for _, der := range chain[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("EK intermediate certificate: %w", err)
		}
		pool.AddCert(cert)
	}
	unhandled := leaf.UnhandledCriticalExtensions[:0]
	for _, oid := range leaf.UnhandledCriticalExtensions {
		if !oid.Equal(oidSubjectAltName) {
			unhandled = append(unhandled, oid)
		}
	}
	leaf.UnhandledCriticalExtensions = unhandled
	// A nil pool would make Verify fall back to the system roots, under which
	// any public CA could pass as a TPM maker.
	if roots == nil {
		return nil, errors.New("no TPM maker roots to verify the EK certificate against")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("EK certificate is not issued by a known TPM maker: %w", err)
	}
	// An EK is a storage key: RSA ones encipher, ECC ones agree on keys (some
	// makers mark ECC EKs keyEncipherment too). Extended key usages, when
	// present, must name the EK certificate purpose.
	if leaf.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) == 0 {
		return nil, errors.New("EK certificate is not for a storage key")
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		if !slices.ContainsFunc(leaf.UnknownExtKeyUsage, oidEKCertificate.Equal) {
			return nil, errors.New("EK certificate is not for an endorsement key")
		}
	}
	return leaf, nil
}

// ekFromCertificate returns the EK in the form the TPM derives it from the
// standard template, so a challenge can be encrypted to it.
func ekFromCertificate(leaf *x509.Certificate) (tpm2.TPMTPublic, error) {
	switch pk := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if pk.N.BitLen() != 2048 || pk.E != 65537 {
			return tpm2.TPMTPublic{}, errors.New("EK certificate holds an unsupported RSA key")
		}
		ek := tpm2.RSAEKTemplate
		ek.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: pk.N.FillBytes(make([]byte, 256))})
		return ek, nil
	case *ecdsa.PublicKey:
		if pk.Curve != elliptic.P256() {
			return tpm2.TPMTPublic{}, errors.New("EK certificate holds an unsupported ECC key")
		}
		point, err := pk.Bytes() // 0x04 || X || Y
		if err != nil {
			return tpm2.TPMTPublic{}, err
		}
		ek := tpm2.ECCEKTemplate
		ek.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: point[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: point[33:]},
		})
		return ek, nil
	default:
		return tpm2.TPMTPublic{}, errors.New("EK certificate holds an unsupported key")
	}
}

// Challenge encrypts a fresh secret to the attested TPM's EK, bound to its
// AK. The device answers with Activate; a matching answer proves the
// certified keys were created by a TPM its maker certified.
func (a *Attestation) Challenge(rand io.Reader) (secret, credentialBlob, encryptedSecret []byte, err error) {
	key, err := tpm2.ImportEncapsulationKey(&a.ek)
	if err != nil {
		return nil, nil, nil, err
	}
	secret = make([]byte, 32)
	if _, err := io.ReadFull(rand, secret); err != nil {
		return nil, nil, nil, err
	}
	credentialBlob, encryptedSecret, err = tpm2.CreateCredential(rand, key, a.akName, secret)
	if err != nil {
		return nil, nil, nil, err
	}
	return secret, credentialBlob, encryptedSecret, nil
}

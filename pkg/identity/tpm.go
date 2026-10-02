package identity

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMBackend shares all commands across platforms; only Open differs.
type TPMBackend struct {
	Open   func() (transport.TPMCloser, error)
	Device string
}

func ecdhTemplate() (tpm2.TPMTPublic, error) {
	p, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}
	if err := (tpm2.PolicyCommandCode{Code: tpm2.TPMCCECDHZGen}).Update(p); err != nil {
		return tpm2.TPMTPublic{}, err
	}
	if err := (tpm2.PolicyAuthValue{}).Update(p); err != nil {
		return tpm2.TPMTPublic{}, err
	}
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: false, AdminWithPolicy: true, NoDA: true, Decrypt: true, SignEncrypt: false},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: p.Hash().Digest},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDH, Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDH, &tpm2.TPMSKeySchemeECDH{HashAlg: tpm2.TPMAlgSHA256})},
			CurveID:   tpm2.TPMECCNistP256, KDF: tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{}),
	}, nil
}

func (b *TPMBackend) Probe() Diagnosis {
	d := Diagnosis{Backend: "tpm", Device: b.Device}
	t, err := b.Open()
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	defer func() { _ = t.Close() }()
	pub, err := ecdhTemplate()
	if err == nil {
		_, err = (tpm2.TestParms{Parameters: tpm2.TPMTPublicParms{Type: pub.Type, Parameters: pub.Parameters}}).Execute(t)
	}
	// The storage primary also needs ECC + AES-CFB support.
	if err == nil {
		_, err = (tpm2.TestParms{Parameters: tpm2.TPMTPublicParms{Type: tpm2.ECCSRKTemplate.Type, Parameters: tpm2.ECCSRKTemplate.Parameters}}).Execute(t)
	}
	if err == nil {
		// Query the command specifically; unsupported ECDH cannot be repaired by creating a key.
		var rsp *tpm2.GetCapabilityResponse
		rsp, err = (tpm2.GetCapability{Capability: tpm2.TPMCapCommands, Property: uint32(tpm2.TPMCCECDHZGen), PropertyCount: 1}).Execute(t)
		if err == nil {
			commands, e := rsp.CapabilityData.Data.Command()
			if e != nil {
				err = e
			} else if len(commands.CommandAttributes) == 0 || commands.CommandAttributes[0].CommandIndex != uint16(tpm2.TPMCCECDHZGen) {
				err = errors.New("TPM does not support ECDH_ZGen")
			}
		}
	}
	if err != nil {
		d.Reason = err.Error()
	} else {
		d.Available = true
	}
	return d
}

func (b *TPMBackend) primary() (transport.TPMCloser, *tpm2.CreatePrimaryResponse, error) {
	t, err := b.Open()
	if err != nil {
		return nil, nil, err
	}
	p, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(t)
	if err != nil {
		_ = t.Close()
		return nil, nil, fmt.Errorf("creating TPM storage primary: %w", err)
	}
	return t, p, nil
}

func flush(t transport.TPM, handle tpm2.TPMHandle) error {
	_, err := (tpm2.FlushContext{FlushHandle: handle}).Execute(t)
	return err
}

func (b *TPMBackend) Create() (Identity, *Metadata, error) {
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
	pub, err := ecdhTemplate()
	if err != nil {
		return nil, nil, err
	}
	created, err := (tpm2.Create{ParentHandle: tpm2.AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}, InPublic: tpm2.New2B(pub)}).Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("creating TPM ECDH child: %w", err)
	}
	createdPublic, err := created.OutPublic.Contents()
	if err != nil {
		return nil, nil, err
	}
	name, err := tpm2.ObjectName(createdPublic)
	if err != nil {
		return nil, nil, err
	}
	md := &Metadata{Version: 1, PublicInfo: PublicInfo{Backend: "tpm", Algorithm: "P-256", Device: b.Device},
		TPMPublic: tpm2.Marshal(created.OutPublic), TPMPrivate: tpm2.Marshal(created.OutPrivate), TPMName: name.Buffer}
	// Release the parent before opening the identity to avoid object-slot pressure.
	if err := flush(t, parent.ObjectHandle); err != nil {
		return nil, nil, err
	}
	parent.ObjectHandle = 0 // The deferred cleanup must not flush the released parent again.
	id, err := b.load(md, false)
	if err != nil {
		return nil, nil, err
	}
	md.Recipient = id.Recipient().String()
	md.PublicKey = id.(*taggedIdentity).key.PublicKey().Bytes()
	return id, md, nil
}

func (b *TPMBackend) Load(md *Metadata) (Identity, error) { return b.load(md, true) }

func (b *TPMBackend) load(md *Metadata, verify bool) (Identity, error) {
	if md.Backend != "tpm" || md.Algorithm != "P-256" {
		return nil, errors.New("invalid TPM backend metadata")
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
	template, err := ecdhTemplate()
	if err != nil {
		return nil, err
	}
	// Compare every security-relevant attribute, policy, scheme and curve.
	expected := template
	expected.Unique = pub.Unique
	if !bytes.Equal(tpm2.Marshal(expected), tpm2.Marshal(*pub)) {
		return nil, errors.New("TPM key does not match ECDH-only template")
	}
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
	pk, err := tpm2.ECDHPub(parms, point)
	if err != nil {
		return nil, err
	}
	if verify && !bytes.Equal(pk.Bytes(), md.PublicKey) {
		return nil, errors.New("TPM public key mismatch")
	}
	t, parent, err := b.primary()
	if err != nil {
		return nil, err
	}
	loaded, err := (tpm2.Load{ParentHandle: tpm2.AuthHandle{Handle: parent.ObjectHandle, Name: parent.Name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}, InPublic: *public, InPrivate: *private}).Execute(t)
	if err != nil {
		_ = flush(t, parent.ObjectHandle)
		_ = t.Close()
		return nil, fmt.Errorf("loading TPM child blob: %w", err)
	}
	parentPublic, err := parent.OutPublic.Contents()
	if err != nil {
		_ = flush(t, loaded.ObjectHandle)
		_ = flush(t, parent.ObjectHandle)
		_ = t.Close()
		return nil, err
	}
	key := &tpmKey{t: t, handle: loaded.ObjectHandle, name: loaded.Name, pk: pk, parent: parent.ObjectHandle, parentPublic: *parentPublic}
	if !bytes.Equal(loaded.Name.Buffer, md.TPMName) {
		_ = key.Close()
		return nil, errors.New("loaded TPM object Name mismatch")
	}
	id, err := NewHardwareIdentity(key)
	if err != nil {
		_ = key.Close()
		return nil, err
	}
	return id, nil
}

type tpmKey struct {
	mu           sync.Mutex
	t            transport.TPMCloser
	handle       tpm2.TPMHandle
	name         tpm2.TPM2BName
	pk           *ecdh.PublicKey
	closed       bool
	parent       tpm2.TPMHandle
	parentPublic tpm2.TPMTPublic
}

func (k *tpmKey) PublicKey() *ecdh.PublicKey { return k.pk }
func (k *tpmKey) Curve() ecdh.Curve          { return ecdh.P256() }
func (k *tpmKey) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, errors.New("TPM key is closed")
	}
	if peer.Curve() != ecdh.P256() {
		return nil, errors.New("ECDH peer must use P-256")
	}
	b := peer.Bytes()
	policy, closeSession, err := tpm2.PolicySession(k.t, tpm2.TPMAlgSHA256, 16, tpm2.Salted(k.parent, k.parentPublic))
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeSession() }()
	if _, err := (tpm2.PolicyCommandCode{PolicySession: policy.Handle(), Code: tpm2.TPMCCECDHZGen}).Execute(k.t); err != nil {
		return nil, err
	}
	if _, err := (tpm2.PolicyAuthValue{PolicySession: policy.Handle()}).Execute(k.t); err != nil {
		return nil, err
	}
	rsp, err := (tpm2.ECDHZGen{KeyHandle: tpm2.AuthHandle{Handle: k.handle, Name: k.name, Auth: policy},
		InPoint: tpm2.New2B(tpm2.TPMSECCPoint{X: tpm2.TPM2BECCParameter{Buffer: b[1:33]}, Y: tpm2.TPM2BECCParameter{Buffer: b[33:]}})}).Execute(k.t)
	if err != nil {
		return nil, err
	}
	p, err := rsp.OutPoint.Contents()
	if err != nil {
		return nil, err
	}
	if len(p.X.Buffer) > 32 {
		return nil, errors.New("invalid TPM ECDH response")
	}
	return new(big.Int).SetBytes(p.X.Buffer).FillBytes(make([]byte, 32)), nil
}
func (k *tpmKey) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	k.closed = true
	return errors.Join(flush(k.t, k.handle), flush(k.t, k.parent), k.t.Close())
}

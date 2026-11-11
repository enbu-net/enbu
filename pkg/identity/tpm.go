package identity

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"sync"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// TPMBackend shares all commands across platforms; only Open differs.
type TPMBackend struct {
	Open   func() (transport.TPMCloser, error)
	Device string

	mu   sync.Mutex
	conn *tpmConn // shared by the loaded keys; nil when none is loaded

	// plainSessions turns parameter encryption off. Only tests set it: the
	// virtual TPM they use computes the HMAC of an encrypted command wrongly.
	plainSessions bool
}

func ecdhTemplate() (tpm2.TPMTPublic, error) {
	p, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return tpm2.TPMTPublic{}, err
	}
	if err := (tpm2.PolicyCommandCode{Code: tpm2.TPMCCECDHZGen}).Update(p); err != nil {
		return tpm2.TPMTPublic{}, err
	}
	// The key has an empty authValue, but without PolicyAuthValue the TPM and
	// go-tpm disagree on the policy session's HMAC key.
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
		// A TPM this user may not open is still a TPM: falling back to a
		// software key would lower the protection over a permission mistake.
		d.Denied = errors.Is(err, fs.ErrPermission)
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

// tpmConn is one TPM connection and its storage primary, shared by every key
// a backend has loaded. Creating the primary is the slowest command enbu sends
// (a key generation, which takes a firmware TPM tens to hundreds of
// milliseconds), and opening the TPM has its own cost through Windows TBS, so
// one operation that loads the identity, its sealed ML-KEM seed, the retained
// identities and the signing key opens the TPM and creates the primary once.
type tpmConn struct {
	// mu serializes commands: a policy session spans several of them.
	mu     sync.Mutex
	t      transport.TPMCloser
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	public tpm2.TPMTPublic
	refs   int // guarded by TPMBackend.mu
	plain  bool
}

// parentAuth authorizes a command with the storage primary as its parent.
func (c *tpmConn) parentAuth() tpm2.AuthHandle {
	return tpm2.AuthHandle{Handle: c.handle, Name: c.name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}
}

// sessionOpts salts a session to the primary and adds the parameter
// encryption encrypt asks for: the session key, and so the parameters, are
// unknown to anyone watching the bus between enbu and the TPM.
func (c *tpmConn) sessionOpts(encrypt tpm2.AuthOption) []tpm2.AuthOption {
	opts := []tpm2.AuthOption{tpm2.Salted(c.handle, c.public)}
	if !c.plain {
		opts = append(opts, encrypt)
	}
	return opts
}

// acquire returns the shared connection, opening the TPM and creating the
// primary when no key holds it. Every acquire is paired with a release.
func (b *TPMBackend) acquire() (*tpmConn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.refs++
		return b.conn, nil
	}
	t, err := b.Open()
	if err != nil {
		return nil, err
	}
	p, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)}, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(t)
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("creating TPM storage primary: %w", err)
	}
	public, err := p.OutPublic.Contents()
	if err == nil {
		err = verifyPrimary(public, p.Name)
	}
	if err != nil {
		_ = flush(t, p.ObjectHandle)
		_ = t.Close()
		return nil, err
	}
	b.conn = &tpmConn{t: t, handle: p.ObjectHandle, name: p.Name, public: *public, refs: 1, plain: b.plainSessions}
	return b.conn, nil
}

// verifyPrimary binds the Name and the public area CreatePrimary returned.
// Sessions are salted to the public key while the pin compares the Name, so a
// response that pairs the genuine Name with another public key must be
// refused: the Name has to be the hash of the public area, and the public area
// has to be the storage template enbu asked for.
func verifyPrimary(public *tpm2.TPMTPublic, reported tpm2.TPM2BName) error {
	expected := tpm2.ECCSRKTemplate
	expected.Unique = public.Unique
	if !bytes.Equal(tpm2.Marshal(expected), tpm2.Marshal(*public)) {
		return errors.New("TPM storage primary does not match the storage template")
	}
	name, err := tpm2.ObjectName(public)
	if err != nil {
		return err
	}
	if !bytes.Equal(name.Buffer, reported.Buffer) {
		return errors.New("TPM storage primary Name does not match its public area")
	}
	return nil
}

// release drops one reference. The last one flushes the primary and closes
// the TPM, so a closed backend holds no TPM resources.
func (b *TPMBackend) release(c *tpmConn) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	c.refs--
	if c.refs > 0 {
		return nil
	}
	if b.conn == c {
		b.conn = nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return errors.Join(flush(c.t, c.handle), c.t.Close())
}

// checkParent compares the primary with the Name pinned when the key was
// created. The primary is derived from the TPM's storage seed, so its Name
// only changes when the TPM is cleared; a different Name means another TPM, or
// something between enbu and the TPM, answered, and salting a session to it
// would hand that party the session key. A key without a pin is refused too:
// it would be salted to whatever primary answered.
func checkParent(c *tpmConn, pinned []byte) error {
	if len(pinned) == 0 {
		return errors.New("TPM key metadata does not pin its storage primary; create a new identity")
	}
	if !bytes.Equal(c.name.Buffer, pinned) {
		return errors.New("TPM storage primary does not match the one this key was created under")
	}
	return nil
}

func flush(t transport.TPM, handle tpm2.TPMHandle) error {
	_, err := (tpm2.FlushContext{FlushHandle: handle}).Execute(t)
	return err
}

// Create makes the ECDH and signing keys under the storage primary.
func (b *TPMBackend) Create(md *Metadata) (HardwareKey, signing.Signer, error) {
	c, err := b.acquire()
	if err != nil {
		return nil, nil, err
	}
	// Load takes its own references, so this one only spans the creation.
	defer func() { _ = b.release(c) }()
	ecdhPub, err := ecdhTemplate()
	if err != nil {
		return nil, nil, err
	}
	keys := &TPMKeys{Parent: c.name.Buffer}
	if keys.ECDH, err = c.create(ecdhPub); err != nil {
		return nil, nil, fmt.Errorf("creating TPM ECDH key: %w", err)
	}
	if keys.Sign, err = c.create(signTemplate()); err != nil {
		return nil, nil, fmt.Errorf("creating TPM signing key: %w", err)
	}
	md.Backend, md.Device, md.TPM = "tpm", b.Device, keys
	return b.Load(md)
}

func (c *tpmConn) create(template tpm2.TPMTPublic) (TPMObject, error) {
	c.mu.Lock()
	created, err := (tpm2.Create{ParentHandle: c.parentAuth(), InPublic: tpm2.New2B(template)}).Execute(c.t)
	c.mu.Unlock()
	if err != nil {
		return TPMObject{}, err
	}
	pub, err := created.OutPublic.Contents()
	if err != nil {
		return TPMObject{}, err
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil {
		return TPMObject{}, err
	}
	return TPMObject{Public: tpm2.Marshal(created.OutPublic), Private: tpm2.Marshal(created.OutPrivate), Name: name.Buffer}, nil
}

// Load loads both keys. Each holds a reference to the shared connection.
func (b *TPMBackend) Load(md *Metadata) (HardwareKey, signing.Signer, error) {
	if md.Backend != "tpm" || md.TPM == nil {
		return nil, nil, errors.New("invalid TPM backend metadata")
	}
	ecdhPub, err := ecdhTemplate()
	if err != nil {
		return nil, nil, err
	}
	k, err := b.load(md.TPM.Parent, md.TPM.ECDH, ecdhPub)
	if err != nil {
		return nil, nil, fmt.Errorf("loading TPM ECDH key: %w", err)
	}
	key := &tpmKey{loaded: k}
	if key.pk, err = tpm2.ECDHPub(k.parms, k.point); err != nil {
		_ = key.Close()
		return nil, nil, err
	}
	s, err := b.load(md.TPM.Parent, md.TPM.Sign, signTemplate())
	if err != nil {
		_ = key.Close()
		return nil, nil, fmt.Errorf("loading TPM signing key: %w", err)
	}
	signer := &tpmSigner{loaded: s}
	pk, err := tpm2.ECDHPub(s.parms, s.point)
	if err == nil {
		signer.pk, err = signing.P256FromUncompressed(pk.Bytes())
	}
	if err != nil {
		_ = key.Close()
		_ = signer.Close()
		return nil, nil, err
	}
	return key, signer, nil
}

// loaded is a TPM object loaded under the shared storage primary.
type loaded struct {
	b      *TPMBackend
	c      *tpmConn
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	parms  *tpm2.TPMSECCParms
	point  *tpm2.TPMSECCPoint
	closed bool // guarded by c.mu
}

// load checks obj against template, so a key made for another use (the
// signing key as the ECDH key, say) or with other attributes is refused, and
// loads it. The Name in obj is unauthenticated metadata: comparing it catches
// edits to the public blob, while the TPM's own Load, which checks the private
// blob against the parent's seed, is what really guards the key.
func (b *TPMBackend) load(parent []byte, obj TPMObject, template tpm2.TPMTPublic) (*loaded, error) {
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](obj.Public)
	if err != nil {
		return nil, fmt.Errorf("TPM public blob: %w", err)
	}
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](obj.Private)
	if err != nil {
		return nil, fmt.Errorf("TPM private blob: %w", err)
	}
	pub, err := public.Contents()
	if err != nil {
		return nil, err
	}
	expected := template
	expected.Unique = pub.Unique
	if !bytes.Equal(tpm2.Marshal(expected), tpm2.Marshal(*pub)) {
		return nil, errors.New("TPM key does not match its template")
	}
	name, err := tpm2.ObjectName(pub)
	if err != nil || !bytes.Equal(name.Buffer, obj.Name) {
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
	c, err := b.acquire()
	if err != nil {
		return nil, err
	}
	if err := checkParent(c, parent); err != nil {
		_ = b.release(c)
		return nil, err
	}
	c.mu.Lock()
	rsp, err := (tpm2.Load{ParentHandle: c.parentAuth(), InPublic: *public, InPrivate: *private}).Execute(c.t)
	c.mu.Unlock()
	if err != nil {
		_ = b.release(c)
		return nil, fmt.Errorf("loading TPM blob: %w", err)
	}
	l := &loaded{b: b, c: c, handle: rsp.ObjectHandle, name: rsp.Name, parms: parms, point: point}
	if !bytes.Equal(rsp.Name.Buffer, obj.Name) {
		_ = l.close()
		return nil, errors.New("loaded TPM object Name mismatch")
	}
	return l, nil
}

func (l *loaded) close() error {
	l.c.mu.Lock()
	if l.closed {
		l.c.mu.Unlock()
		return nil
	}
	l.closed = true
	err := flush(l.c.t, l.handle)
	l.c.mu.Unlock()
	return errors.Join(err, l.b.release(l.c))
}

type tpmKey struct {
	*loaded
	pk *ecdh.PublicKey
}

func (k *tpmKey) PublicKey() *ecdh.PublicKey { return k.pk }
func (k *tpmKey) Curve() ecdh.Curve          { return ecdh.P256() }
func (k *tpmKey) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	if peer.Curve() != ecdh.P256() {
		return nil, errors.New("ECDH peer must use P-256")
	}
	c := k.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if k.closed {
		return nil, errors.New("TPM key is closed")
	}
	b := peer.Bytes()
	// The session is salted to the primary and encrypts the response, so the
	// shared secret does not cross the bus in the clear.
	policy, closeSession, err := tpm2.PolicySession(c.t, tpm2.TPMAlgSHA256, 16,
		c.sessionOpts(tpm2.AESEncryption(128, tpm2.EncryptOut))...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = closeSession() }()
	if _, err := (tpm2.PolicyCommandCode{PolicySession: policy.Handle(), Code: tpm2.TPMCCECDHZGen}).Execute(c.t); err != nil {
		return nil, err
	}
	if _, err := (tpm2.PolicyAuthValue{PolicySession: policy.Handle()}).Execute(c.t); err != nil {
		return nil, err
	}
	rsp, err := (tpm2.ECDHZGen{KeyHandle: tpm2.AuthHandle{Handle: k.handle, Name: k.name, Auth: policy},
		InPoint: tpm2.New2B(tpm2.TPMSECCPoint{X: tpm2.TPM2BECCParameter{Buffer: b[1:33]}, Y: tpm2.TPM2BECCParameter{Buffer: b[33:]}})}).Execute(c.t)
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

func (k *tpmKey) Close() error { return k.close() }

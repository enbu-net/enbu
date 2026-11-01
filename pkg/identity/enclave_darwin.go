//go:build darwin

package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// securityAPI owns the process-lifetime framework handles. Every returned CF
// reference is released by the operation that acquired it.
type securityAPI struct {
	security, core uintptr
	release        func(uintptr)
	dataCreate     func(uintptr, *byte, int64) uintptr
	dataLength     func(uintptr) int64
	dataBytes      func(uintptr) uintptr
	dictCreate     func(uintptr, int64, uintptr, uintptr) uintptr
	dictSet        func(uintptr, uintptr, uintptr)
	dictGet        func(uintptr, uintptr) uintptr
	equal          func(uintptr, uintptr) bool
	numberCreate   func(uintptr, int64, *int32) uintptr
	accessCreate   func(uintptr, uintptr, uint64, *uintptr) uintptr
	keyCreate      func(uintptr, *uintptr) uintptr
	keyPublic      func(uintptr) uintptr
	keyExternal    func(uintptr, *uintptr) uintptr
	keyAttributes  func(uintptr) uintptr
	keyWithData    func(uintptr, uintptr, *uintptr) uintptr
	keyExchange    func(uintptr, uintptr, uintptr, uintptr, *uintptr) uintptr
	keySign        func(uintptr, uintptr, uintptr, *uintptr) uintptr
	keySupported   func(uintptr, int64, uintptr) bool
	stringCreate   func(uintptr, string, uint32) uintptr
	errorCode      func(uintptr) int64
	constants      sync.Map
}

var loadSecurity = sync.OnceValues(func() (*securityAPI, error) {
	s, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	c, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	a := &securityAPI{security: s, core: c}
	for _, f := range []struct {
		target any
		lib    uintptr
		name   string
	}{
		{&a.release, c, "CFRelease"}, {&a.dataCreate, c, "CFDataCreate"}, {&a.dataLength, c, "CFDataGetLength"}, {&a.dataBytes, c, "CFDataGetBytePtr"},
		{&a.dictCreate, c, "CFDictionaryCreateMutable"}, {&a.dictSet, c, "CFDictionarySetValue"}, {&a.dictGet, c, "CFDictionaryGetValue"}, {&a.equal, c, "CFEqual"}, {&a.numberCreate, c, "CFNumberCreate"},
		{&a.accessCreate, s, "SecAccessControlCreateWithFlags"}, {&a.keyCreate, s, "SecKeyCreateRandomKey"}, {&a.keyPublic, s, "SecKeyCopyPublicKey"}, {&a.keyExternal, s, "SecKeyCopyExternalRepresentation"},
		{&a.keyAttributes, s, "SecKeyCopyAttributes"}, {&a.keyWithData, s, "SecKeyCreateWithData"}, {&a.keyExchange, s, "SecKeyCopyKeyExchangeResult"}, {&a.keySign, s, "SecKeyCreateSignature"}, {&a.keySupported, s, "SecKeyIsAlgorithmSupported"},
		{&a.stringCreate, c, "CFStringCreateWithCString"},
		{&a.errorCode, c, "CFErrorGetCode"},
	} {
		ptr, err := purego.Dlsym(f.lib, f.name)
		if err != nil {
			return nil, err
		}
		purego.RegisterFunc(f.target, ptr)
	}
	return a, nil
})

// constant returns a framework constant. The lookups are cached: every key
// operation needs several of them.
func (a *securityAPI) constant(name string) uintptr {
	if v, ok := a.constants.Load(name); ok {
		return v.(uintptr)
	}
	v := a.lookupConstant(name)
	a.constants.Store(name, v)
	return v
}

func (a *securityAPI) lookupConstant(name string) uintptr {
	lib := a.security
	if name[0:3] == "kCF" {
		lib = a.core
	}
	p, err := purego.Dlsym(lib, name)
	if err != nil {
		panic(err)
	} // Framework ABI constants must exist on supported macOS.
	return *(*uintptr)(unsafe.Pointer(p))
}
func (a *securityAPI) dictionary() uintptr {
	k, _ := purego.Dlsym(a.core, "kCFTypeDictionaryKeyCallBacks")
	v, _ := purego.Dlsym(a.core, "kCFTypeDictionaryValueCallBacks")
	return a.dictCreate(0, 0, k, v)
}
func (a *securityAPI) set(d uintptr, name string, value uintptr) {
	a.dictSet(d, a.constant(name), value)
}
func (a *securityAPI) data(b []byte) uintptr {
	if len(b) == 0 {
		return a.dataCreate(0, nil, 0)
	}
	d := a.dataCreate(0, &b[0], int64(len(b)))
	runtime.KeepAlive(b)
	return d
}
func (a *securityAPI) bytes(d uintptr) []byte {
	n := a.dataLength(d)
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(a.dataBytes(d))), int(n))...)
}
func (a *securityAPI) nativeError(ref uintptr, op string) error {
	if ref != 0 {
		code := a.errorCode(ref)
		a.release(ref)
		return fmt.Errorf("Security framework %s failed (code %d)", op, code)
	}
	return fmt.Errorf("Security framework %s failed", op)
}

type enclaveBackend struct{}

// enclaveTokenObject is the key attribute that carries a Secure Enclave key's
// wrapped private key, the same blob CryptoKit calls dataRepresentation. Apple
// does not name it in the public headers. Passing it back to SecKeyCreateWithData
// restores the key; without it the Secure Enclave silently makes a new one, so
// every restore is checked against the expected public key.
const enclaveTokenObject = "toid"

func (b *enclaveBackend) Probe() Diagnosis {
	d := Diagnosis{Backend: "secure-enclave", Device: "Secure Enclave"}
	k, blob, err := b.generate()
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	defer func() { _ = k.Close() }()
	if !k.api.keySupported(k.ref, 4, k.api.constant("kSecKeyAlgorithmECDHKeyExchangeStandard")) {
		d.Reason = "Secure Enclave does not support P-256 ECDH"
		return d
	}
	// A key that cannot be restored from its blob would be lost when enbu
	// exits, so the probe checks the whole round trip before any identity is
	// created. Nothing is written to the Keychain or the disk.
	restored, err := b.restore(blob, samePoint(k.pk.Bytes()))
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	_ = restored.Close()
	d.Available = true
	return d
}

// generate creates a Secure Enclave P-256 key and returns it with its wrapped
// private key. The key is not stored in the Keychain: the data-protection
// Keychain needs a provisioning profile that a standalone or ad-hoc signed
// executable cannot carry, and the wrapped key is useless off this Mac.
func (b *enclaveBackend) generate() (*enclaveKey, []byte, error) {
	a, err := loadSecurity()
	if err != nil {
		return nil, nil, err
	}
	attrs, priv := a.dictionary(), a.dictionary()
	defer a.release(attrs)
	defer a.release(priv)
	var nativeErr uintptr
	access := a.accessCreate(0, a.constant("kSecAttrAccessibleWhenUnlockedThisDeviceOnly"), 1<<30, &nativeErr) // kSecAccessControlPrivateKeyUsage
	if access == 0 {
		return nil, nil, a.nativeError(nativeErr, "access control")
	}
	defer a.release(access)
	a.set(priv, "kSecAttrAccessControl", access)
	a.set(priv, "kSecAttrIsPermanent", a.constant("kCFBooleanFalse"))
	a.set(attrs, "kSecPrivateKeyAttrs", priv)
	a.set(attrs, "kSecAttrTokenID", a.constant("kSecAttrTokenIDSecureEnclave"))
	a.set(attrs, "kSecAttrKeyType", a.constant("kSecAttrKeyTypeECSECPrimeRandom"))
	size := int32(256)
	n := a.numberCreate(0, 3, &size) // kCFNumberSInt32Type
	defer a.release(n)
	a.set(attrs, "kSecAttrKeySizeInBits", n)
	ref := a.keyCreate(attrs, &nativeErr)
	if ref == 0 {
		return nil, nil, a.nativeError(nativeErr, "Secure Enclave key creation")
	}
	blob, err := a.tokenObject(ref)
	if err != nil {
		a.release(ref)
		return nil, nil, err
	}
	k, err := a.wrapKey(ref)
	if err != nil {
		return nil, nil, err
	}
	return k, blob, nil
}

// tokenObject returns the wrapped private key of a Secure Enclave key.
func (a *securityAPI) tokenObject(ref uintptr) ([]byte, error) {
	attrs := a.keyAttributes(ref)
	if attrs == 0 {
		return nil, errors.New("Secure Enclave key attributes unavailable")
	}
	defer a.release(attrs)
	token := a.dictGet(attrs, a.constant("kSecAttrTokenID"))
	if token == 0 || !a.equal(token, a.constant("kSecAttrTokenIDSecureEnclave")) {
		return nil, errors.New("key is not a Secure Enclave key")
	}
	name := a.stringCreate(0, enclaveTokenObject, 0x08000100) // kCFStringEncodingUTF8
	if name == 0 {
		return nil, errors.New("CFString creation failed")
	}
	defer a.release(name)
	blob := a.dictGet(attrs, name)
	if blob == 0 {
		return nil, errors.New("Secure Enclave key has no wrapped key data")
	}
	out := a.bytes(blob)
	if len(out) == 0 {
		return nil, errors.New("Secure Enclave key has no wrapped key data")
	}
	return out, nil
}

// samePoint matches an uncompressed P-256 public key.
func samePoint(want []byte) func([]byte) bool {
	return func(got []byte) bool { return bytes.Equal(got, want) }
}

// restore rebuilds a Secure Enclave key from its wrapped private key and
// refuses it unless expected accepts its uncompressed public key.
func (b *enclaveBackend) restore(blob []byte, expected func([]byte) bool) (*enclaveKey, error) {
	if len(blob) == 0 {
		return nil, errors.New("missing Secure Enclave key data")
	}
	a, err := loadSecurity()
	if err != nil {
		return nil, err
	}
	attrs := a.dictionary()
	defer a.release(attrs)
	a.set(attrs, "kSecAttrTokenID", a.constant("kSecAttrTokenIDSecureEnclave"))
	a.set(attrs, "kSecAttrKeyType", a.constant("kSecAttrKeyTypeECSECPrimeRandom"))
	a.set(attrs, "kSecAttrKeyClass", a.constant("kSecAttrKeyClassPrivate"))
	name := a.stringCreate(0, enclaveTokenObject, 0x08000100)
	if name == 0 {
		return nil, errors.New("CFString creation failed")
	}
	defer a.release(name)
	d := a.data(blob)
	defer a.release(d)
	a.dictSet(attrs, name, d)
	var nativeErr uintptr
	ref := a.keyWithData(d, attrs, &nativeErr)
	if ref == 0 {
		return nil, a.nativeError(nativeErr, "Secure Enclave key restore")
	}
	if _, err := a.tokenObject(ref); err != nil {
		a.release(ref)
		return nil, err
	}
	k, err := a.wrapKey(ref)
	if err != nil {
		return nil, err
	}
	if !expected(k.pk.Bytes()) {
		_ = k.Close()
		return nil, errors.New("Secure Enclave key data does not match the saved public key (was this identity created on another Mac?)")
	}
	return k, nil
}

func (a *securityAPI) wrapKey(ref uintptr) (*enclaveKey, error) {
	public := a.keyPublic(ref)
	if public == 0 {
		a.release(ref)
		return nil, errors.New("Secure Enclave public key unavailable")
	}
	defer a.release(public)
	var nativeErr uintptr
	data := a.keyExternal(public, &nativeErr) // Only the public key is exported.
	if data == 0 {
		a.release(ref)
		return nil, a.nativeError(nativeErr, "public key encoding")
	}
	defer a.release(data)
	pk, err := ecdh.P256().NewPublicKey(a.bytes(data))
	if err != nil {
		a.release(ref)
		return nil, err
	}
	return &enclaveKey{api: a, ref: ref, pk: pk}, nil
}

func (b *enclaveBackend) Create() (Identity, *Metadata, error) {
	k, blob, err := b.generate()
	if err != nil {
		return nil, nil, err
	}
	id, err := NewHardwareIdentity(k)
	if err != nil {
		_ = k.Close()
		return nil, nil, err
	}
	md := &Metadata{Version: 1, PublicInfo: PublicInfo{Backend: "secure-enclave", Algorithm: "P-256", Recipient: id.Recipient().String(), Device: "Secure Enclave"}, PublicKey: k.pk.Bytes(), EnclaveKey: blob}
	return id, md, nil
}

func (b *enclaveBackend) Load(md *Metadata) (Identity, error) {
	k, err := b.loadKey(md)
	if err != nil {
		return nil, err
	}
	id, err := NewHardwareIdentity(k)
	if err != nil {
		_ = k.Close()
	}
	return id, err
}

func (b *enclaveBackend) loadKey(md *Metadata) (*enclaveKey, error) {
	if md.Backend != "secure-enclave" || !hardwareAlgorithm(md.Algorithm) || len(md.EnclaveKey) == 0 {
		return nil, errors.New("invalid Secure Enclave metadata (identities from before enbu kept Secure Enclave keys out of the Keychain must be created again)")
	}
	return b.restore(md.EnclaveKey, samePoint(md.PublicKey))
}

// SealSeed encrypts the ML-KEM seed to the identity's Secure Enclave key, so
// that opening it needs the same Secure Enclave, like a TPM-sealed seed.
func (b *enclaveBackend) SealSeed(md *Metadata, seed []byte) error {
	if len(seed) != mlkem.SeedSize {
		return errors.New("ML-KEM seed must be 64 bytes")
	}
	pub, err := ecdh.P256().NewPublicKey(md.PublicKey)
	if err != nil {
		return fmt.Errorf("Secure Enclave public key: %w", err)
	}
	sealed, err := sealToECDH(pub, seed)
	if err != nil {
		return err
	}
	md.EnclaveSeal = sealed
	return nil
}

func (b *enclaveBackend) UnsealSeed(md *Metadata) ([]byte, error) {
	if len(md.EnclaveSeal) == 0 {
		return nil, errors.New("hybrid identity metadata has no sealed ML-KEM seed")
	}
	k, err := b.loadKey(md)
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	seed, err := openFromECDH(k, md.EnclaveSeal)
	if err != nil {
		return nil, err
	}
	if len(seed) != mlkem.SeedSize {
		clear(seed)
		return nil, errors.New("sealed ML-KEM seed has the wrong size")
	}
	return seed, nil
}

type enclaveKey struct {
	mu  sync.Mutex
	api *securityAPI
	ref uintptr
	pk  *ecdh.PublicKey
}

func (k *enclaveKey) PublicKey() *ecdh.PublicKey { return k.pk }
func (k *enclaveKey) Curve() ecdh.Curve          { return ecdh.P256() }
func (k *enclaveKey) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ref != 0 {
		k.api.release(k.ref)
		k.ref = 0
	}
	return nil
}
func (k *enclaveKey) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ref == 0 {
		return nil, errors.New("Secure Enclave key is closed")
	}
	if peer.Curve() != ecdh.P256() {
		return nil, errors.New("ECDH peer must use P-256")
	}
	a := k.api
	d := a.data(peer.Bytes())
	defer a.release(d)
	attrs := a.dictionary()
	defer a.release(attrs)
	a.set(attrs, "kSecAttrKeyType", a.constant("kSecAttrKeyTypeECSECPrimeRandom"))
	a.set(attrs, "kSecAttrKeyClass", a.constant("kSecAttrKeyClassPublic"))
	var nativeErr uintptr
	pub := a.keyWithData(d, attrs, &nativeErr)
	if pub == 0 {
		return nil, a.nativeError(nativeErr, "ECDH peer import")
	}
	defer a.release(pub)
	params := a.dictionary()
	defer a.release(params)
	result := a.keyExchange(k.ref, a.constant("kSecKeyAlgorithmECDHKeyExchangeStandard"), pub, params, &nativeErr)
	if result == 0 {
		return nil, a.nativeError(nativeErr, "ECDH")
	}
	defer a.release(result)
	out := a.bytes(result)
	if len(out) != 32 {
		return nil, errors.New("invalid Secure Enclave ECDH response")
	}
	return out, nil
}

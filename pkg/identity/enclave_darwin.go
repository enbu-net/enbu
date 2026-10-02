//go:build darwin

package identity

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
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
	keySupported   func(uintptr, int64, uintptr) bool
	itemCopy       func(uintptr, *uintptr) int32
	itemDelete     func(uintptr) int32
	errorCode      func(uintptr) int64
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
		{&a.keyAttributes, s, "SecKeyCopyAttributes"}, {&a.keyWithData, s, "SecKeyCreateWithData"}, {&a.keyExchange, s, "SecKeyCopyKeyExchangeResult"}, {&a.keySupported, s, "SecKeyIsAlgorithmSupported"},
		{&a.itemCopy, s, "SecItemCopyMatching"}, {&a.itemDelete, s, "SecItemDelete"},
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

func (a *securityAPI) constant(name string) uintptr {
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

func (b *enclaveBackend) Probe() Diagnosis {
	d := Diagnosis{Backend: "secure-enclave", Device: "Secure Enclave"}
	a, err := loadSecurity()
	if err == nil {
		err = a.probeKeychainAccess()
	}
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	k, err := b.generate("", false)
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	defer func() { _ = k.Close() }()
	// Validate ECDH support without persisting a Keychain entry.
	d.Available = k.api.keySupported(k.ref, 4, k.api.constant("kSecKeyAlgorithmECDHKeyExchangeStandard"))
	if !d.Available {
		d.Reason = "Secure Enclave does not support P-256 ECDH"
	}
	return d
}

func (b *enclaveBackend) generate(reference string, permanent bool) (*enclaveKey, error) {
	a, err := loadSecurity()
	if err != nil {
		return nil, err
	}
	attrs, priv := a.dictionary(), a.dictionary()
	defer a.release(attrs)
	defer a.release(priv)
	var nativeErr uintptr
	access := a.accessCreate(0, a.constant("kSecAttrAccessibleWhenUnlockedThisDeviceOnly"), 1<<30, &nativeErr)
	if access == 0 {
		return nil, a.nativeError(nativeErr, "access control")
	}
	defer a.release(access)
	a.set(priv, "kSecAttrAccessControl", access)
	if permanent {
		a.set(priv, "kSecAttrIsPermanent", a.constant("kCFBooleanTrue"))
		tag := a.data([]byte(reference))
		defer a.release(tag)
		a.set(priv, "kSecAttrApplicationTag", tag)
	} else {
		a.set(priv, "kSecAttrIsPermanent", a.constant("kCFBooleanFalse"))
	}
	a.set(attrs, "kSecPrivateKeyAttrs", priv)
	a.set(attrs, "kSecUseDataProtectionKeychain", a.constant("kCFBooleanTrue"))
	a.set(attrs, "kSecAttrTokenID", a.constant("kSecAttrTokenIDSecureEnclave"))
	a.set(attrs, "kSecAttrKeyType", a.constant("kSecAttrKeyTypeECSECPrimeRandom"))
	size := int32(256)
	n := a.numberCreate(0, 3, &size) // kCFNumberSInt32Type
	defer a.release(n)
	a.set(attrs, "kSecAttrKeySizeInBits", n)
	ref := a.keyCreate(attrs, &nativeErr)
	if ref == 0 {
		return nil, a.nativeError(nativeErr, "Secure Enclave key creation")
	}
	return a.wrapKey(ref)
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
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return nil, nil, err
	}
	ref := "enbu.identity.v1." + hex.EncodeToString(buf)
	k, err := b.generate(ref, true)
	if err != nil {
		return nil, nil, err
	}
	id, err := NewHardwareIdentity(k)
	if err != nil {
		_ = k.Close()
		return nil, nil, err
	}
	md := &Metadata{Version: 1, PublicInfo: PublicInfo{Backend: "secure-enclave", Algorithm: "P-256", Recipient: id.Recipient().String(), Device: "Secure Enclave"}, PublicKey: k.pk.Bytes(), Reference: ref}
	return id, md, nil
}

func (a *securityAPI) keyQuery(reference string) uintptr {
	q := a.dictionary()
	a.set(q, "kSecUseDataProtectionKeychain", a.constant("kCFBooleanTrue"))
	a.set(q, "kSecClass", a.constant("kSecClassKey"))
	a.set(q, "kSecAttrKeyType", a.constant("kSecAttrKeyTypeECSECPrimeRandom"))
	a.set(q, "kSecAttrKeyClass", a.constant("kSecAttrKeyClassPrivate"))
	tag := a.data([]byte(reference))
	a.set(q, "kSecAttrApplicationTag", tag)
	a.release(tag)
	return q
}

// Secure Enclave persistence uses the data-protection Keychain, whose access
// depends on the host executable's signing entitlements. A transient key alone
// does not test that access. Probe with a read-only query so doctor never leaves
// a permanent key behind, even if interrupted before cleanup could run.
func (a *securityAPI) probeKeychainAccess() error {
	q := a.keyQuery("enbu.identity.probe")
	defer a.release(q)
	a.set(q, "kSecUseAuthenticationUI", a.constant("kSecUseAuthenticationUIFail"))
	a.set(q, "kSecReturnRef", a.constant("kCFBooleanTrue"))
	var ref uintptr
	status := a.itemCopy(q, &ref)
	if ref != 0 {
		a.release(ref)
	}
	if status != 0 && status != -25300 { // errSecItemNotFound still proves query access.
		return fmt.Errorf("Secure Enclave data-protection Keychain unavailable: OSStatus %d (check code-signing entitlements and login session)", status)
	}
	return nil
}

func (b *enclaveBackend) Load(md *Metadata) (Identity, error) {
	if md.Backend != "secure-enclave" || md.Algorithm != "P-256" || md.Reference == "" {
		return nil, errors.New("invalid Secure Enclave metadata")
	}
	a, err := loadSecurity()
	if err != nil {
		return nil, err
	}
	q := a.keyQuery(md.Reference)
	defer a.release(q)
	a.set(q, "kSecReturnRef", a.constant("kCFBooleanTrue"))
	var ref uintptr
	if status := a.itemCopy(q, &ref); status != 0 {
		return nil, fmt.Errorf("loading Secure Enclave Keychain reference: OSStatus %d", status)
	}
	attrs := a.keyAttributes(ref)
	if attrs == 0 {
		a.release(ref)
		return nil, errors.New("Secure Enclave key attributes unavailable")
	}
	token := a.dictGet(attrs, a.constant("kSecAttrTokenID"))
	valid := token != 0 && a.equal(token, a.constant("kSecAttrTokenIDSecureEnclave"))
	a.release(attrs)
	if !valid {
		a.release(ref)
		return nil, errors.New("saved key is not a Secure Enclave key")
	}
	k, err := a.wrapKey(ref)
	if err != nil {
		return nil, err
	}
	id, err := NewHardwareIdentity(k)
	if err != nil {
		_ = k.Close()
	}
	return id, err
}

// Delete is used only to roll back an unsaved Keychain reference and by native
// integration tests. It never exports or obtains private key material.
func (b *enclaveBackend) Delete(md *Metadata) error {
	a, err := loadSecurity()
	if err != nil {
		return err
	}
	q := a.keyQuery(md.Reference)
	defer a.release(q)
	if status := a.itemDelete(q); status != 0 && status != -25300 {
		return fmt.Errorf("deleting Secure Enclave reference: OSStatus %d", status)
	}
	return nil
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

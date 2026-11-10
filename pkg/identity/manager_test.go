package identity

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/signing"
)

type memoryVault map[string][]byte

func (v memoryVault) Store(_, key string, b []byte) error { v[key] = bytes.Clone(b); return nil }
func (v memoryVault) Load(_, key string) ([]byte, error) {
	b, ok := v[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (v memoryVault) Delete(_, key string) error  { delete(v, key); return nil }
func (v memoryVault) Probe(context.Context) error { return nil }

// softwareHardwareKey is a P-256 key in memory standing in for a hardware key.
type softwareHardwareKey struct {
	*ecdh.PrivateKey
	closed bool
	calls  int
}

func (k *softwareHardwareKey) ECDH(p *ecdh.PublicKey) ([]byte, error) {
	k.calls++
	return k.PrivateKey.ECDH(p)
}
func (k *softwareHardwareKey) Close() error { k.closed = true; return nil }

// fakeHardware keeps its keys in memory, indexed by the blob it records in
// the metadata, like the Secure Enclave backend.
type fakeHardware struct {
	unavailable bool
	createError error
	creates     int
	loads       int
	ecdh        map[string]*ecdh.PrivateKey
	sign        map[string]signing.Signer
}

func newFakeHardware() *fakeHardware {
	return &fakeHardware{ecdh: map[string]*ecdh.PrivateKey{}, sign: map[string]signing.Signer{}}
}

func (h *fakeHardware) Probe() Diagnosis {
	if h.unavailable {
		return Diagnosis{Backend: "secure-enclave", Reason: "no Secure Enclave"}
	}
	return Diagnosis{Backend: "secure-enclave", Available: true}
}

func (h *fakeHardware) Create(md *Metadata) (HardwareKey, signing.Signer, error) {
	h.creates++
	if h.createError != nil {
		return nil, nil, h.createError
	}
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	s, err := newP256Signer()
	if err != nil {
		return nil, nil, err
	}
	blob := make([]byte, 16)
	_, _ = rand.Read(blob)
	h.ecdh[string(blob)], h.sign[string(blob)] = k, s
	md.Backend, md.Device, md.Enclave = "secure-enclave", "fake", &EnclaveKeys{ECDH: blob, Sign: blob}
	return &softwareHardwareKey{PrivateKey: k}, s, nil
}

func (h *fakeHardware) Load(md *Metadata) (HardwareKey, signing.Signer, error) {
	h.loads++
	if md.Enclave == nil {
		return nil, nil, errors.New("no key data")
	}
	k, ok := h.ecdh[string(md.Enclave.ECDH)]
	if !ok {
		return nil, nil, errors.New("unknown key data")
	}
	return &softwareHardwareKey{PrivateKey: k}, h.sign[string(md.Enclave.Sign)], nil
}

func newP256Signer() (signing.Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return signing.NewP256Signer(k)
}

func newManager(t *testing.T) *Manager {
	t.Helper()
	h := newFakeHardware()
	h.unavailable = true
	return &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: h}
}

func roundTrip(t *testing.T, d *Device, recipient string) {
	t.Helper()
	ct, err := age.EncryptForPublicKeys([]byte("secret"), []string{recipient})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := age.Decrypt(ct, d.Identity); err != nil || string(out) != "secret" {
		t.Fatalf("decrypt: %q %v", out, err)
	}
	sig, err := d.Signer.Sign(signing.DomainState, []byte("x"))
	if err != nil || signing.Verify(d.Signer.Public(), signing.DomainState, []byte("x"), sig) != nil {
		t.Fatalf("sign: %v", err)
	}
}

func TestManagerSoftwareFallbackReuseAndMetadata(t *testing.T) {
	m := newManager(t)
	d, info, warning, err := m.Create("owner/repo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if !info.Created || info.Backend != "keyring" || info.Algorithm != "MLKEM768-X25519" || !strings.HasPrefix(info.Recipient, "age1pq1") {
		t.Fatalf("info: %+v", info)
	}
	if !strings.Contains(warning, "no Secure Enclave") || !strings.Contains(warning, "OS keyring") {
		t.Fatalf("warning: %q", warning)
	}
	if info.DeviceID != string(d.Signer.Public().DeviceID()) || info.Fingerprint == "" {
		t.Fatalf("device id: %+v", info)
	}
	roundTrip(t, d, info.Recipient)

	again, info2, warning, err := m.Create("owner/repo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	if info2.Created || info2.Recipient != info.Recipient || info2.DeviceID != info.DeviceID || warning != "" {
		t.Fatalf("did not reuse: %+v %q", info2, warning)
	}
	roundTrip(t, again, info.Recipient)
	if got, err := m.Info("owner/repo"); err != nil || got.DeviceID != info.DeviceID {
		t.Fatalf("Info = %+v %v", got, err)
	}

	stat, err := os.Stat(m.Path("owner/repo"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports synthesized mode bits; access is controlled by ACLs.
	if runtime.GOOS != "windows" && stat.Mode().Perm()&0o077 != 0 {
		t.Fatalf("metadata permissions: %v", stat.Mode())
	}
	saved, _ := os.ReadFile(m.Path("owner/repo"))
	for _, secret := range m.Vault.(memoryVault) {
		if bytes.Contains(saved, secret) || bytes.Contains(saved, []byte("AGE-SECRET")) {
			t.Fatal("private key stored in metadata")
		}
	}
}

func TestManagerCreatesHybridHardwareDevice(t *testing.T) {
	h := newFakeHardware()
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: h}
	d, info, warning, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if info.Backend != "secure-enclave" || info.Algorithm != "MLKEM768-P256" || !strings.HasPrefix(info.Recipient, "age1tagpq1") || warning != "" {
		t.Fatalf("info: %+v %q", info, warning)
	}
	roundTrip(t, d, info.Recipient)
	_ = d.Close()
	if len(m.Vault.(memoryVault)) != 0 {
		t.Fatal("a hardware device put key material in the keyring")
	}
	md, err := m.read("o/r")
	if err != nil || len(md.SealedSeed) == 0 {
		t.Fatalf("the ML-KEM seed is not sealed: %+v %v", md, err)
	}
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, loaded, info.Recipient)
	_ = loaded.Close()

	md.SealedSeed[len(md.SealedSeed)-1] ^= 1
	if err := saveJSON(m.Path("o/r"), md); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("loaded a device with a corrupted sealed seed")
	}
}

func TestManagerNeverReplacesSavedOrPartiallyCreatedKey(t *testing.T) {
	for _, mode := range []string{"auto", "hardware"} {
		t.Run(mode, func(t *testing.T) {
			h := newFakeHardware()
			h.createError = errors.New("creation failed")
			m := &Manager{Dir: t.TempDir(), Mode: mode, Vault: memoryVault{}, Hardware: h}
			if _, _, _, err := m.Create("o/r"); err == nil {
				t.Fatal("silently fell back after create failure")
			}
			if len(m.Vault.(memoryVault)) != 0 {
				t.Fatal("created fallback key")
			}
			md := &Metadata{Backend: "secure-enclave", Algorithm: algHardware, Recipient: "saved", SigningKey: mustSigner(t).Public(), Enclave: &EnclaveKeys{}}
			if err := saveJSON(m.Path("o/r"), md); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := m.Create("o/r"); err == nil {
				t.Fatal("silently replaced broken saved key")
			}
			if h.creates != 1 || h.loads != 1 {
				t.Fatalf("calls: creates %d loads %d", h.creates, h.loads)
			}
		})
	}
}

func mustSigner(t *testing.T) signing.Signer {
	t.Helper()
	s, err := newP256Signer()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestManagerDetectsTampering(t *testing.T) {
	for _, field := range []string{"recipient", "signing_key", "reference", "secret", "algorithm", "empty"} {
		t.Run(field, func(t *testing.T) {
			m := newManager(t)
			d, _, _, err := m.Create("o/r")
			if err != nil {
				t.Fatal(err)
			}
			_ = d.Close()
			md, err := m.read("o/r")
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "recipient":
				other, _ := agecrypto.GenerateHybridIdentity()
				md.Recipient = other.Recipient().String()
			case "signing_key":
				md.SigningKey = mustSigner(t).Public()
			case "reference":
				md.Reference = "missing"
			case "secret":
				m.Vault.(memoryVault)[md.Reference] = []byte("corrupt")
			case "algorithm":
				md.Algorithm = algHardware
			case "empty":
				md.Recipient = ""
			}
			if err := saveJSON(m.Path("o/r"), md); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(m.Path("o/r"))
			if _, _, _, err := m.Create("o/r"); err == nil {
				t.Fatal("accepted tampered identity")
			}
			after, _ := os.ReadFile(m.Path("o/r"))
			if !bytes.Equal(before, after) {
				t.Fatal("replaced saved metadata")
			}
		})
	}
}

func TestBackendSelectionAndDoctor(t *testing.T) {
	m := newManager(t)
	m.Mode = "hardware"
	if _, _, _, err := m.Create("o/r"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("hardware mode fell back: %v", err)
	}
	m.Mode = "unknown"
	if _, _, _, err := m.Create("o/r"); err == nil {
		t.Fatal("accepted invalid mode")
	}
	m.Mode = "keyring"
	m.Hardware.(*fakeHardware).unavailable = false
	d, info, warning, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if info.Backend != "keyring" || warning != "" {
		t.Fatalf("explicit keyring: %+v %q", info, warning)
	}
	m.Mode = "hardware"
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("hardware mode loaded keyring identity")
	}
	diag := m.Doctor(context.Background())
	if !diag.Available || !diag.FallbackAvailable {
		t.Fatalf("doctor: %+v", diag)
	}
	if m.Hardware.(*fakeHardware).creates != 0 {
		t.Fatal("doctor created a key")
	}
}

func newHybridHardware(t *testing.T) (Identity, *softwareHardwareKey) {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &softwareHardwareKey{PrivateKey: k}
	seed := make([]byte, mlkem.SeedSize)
	_, _ = rand.Read(seed)
	id, err := NewHybridHardwareIdentity(h, seed)
	if err != nil {
		t.Fatal(err)
	}
	return id, h
}

func TestHybridHardwareIdentityUsesBothKeys(t *testing.T) {
	id, h := newHybridHardware(t)
	soft, err := agecrypto.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := age.EncryptForPublicKeys([]byte("hybrid"), []string{id.Recipient().String(), soft.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ct), "-> mlkem768p256tag ") {
		t.Fatal("no tagged hybrid stanza")
	}
	for _, i := range []agecrypto.Identity{id, soft} {
		if out, err := age.Decrypt(ct, i); err != nil || string(out) != "hybrid" {
			t.Fatalf("decrypt: %q %v", out, err)
		}
	}
	if h.calls != 1 {
		t.Fatalf("hardware ECDH calls = %d, want 1", h.calls)
	}
	// The hardware half alone is not enough.
	seed := make([]byte, mlkem.SeedSize)
	_, _ = rand.Read(seed)
	sameDevice, err := NewHybridHardwareIdentity(h, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(ct, sameDevice); err == nil {
		t.Fatal("decrypted without the matching ML-KEM key")
	}
	if _, err := id.Unwrap([]*agecrypto.Stanza{{Type: "mlkem768p256tag"}}); err == nil || errors.Is(err, agecrypto.ErrIncorrectIdentity) {
		t.Fatalf("malformed stanza: %v", err)
	}
	if err := id.Close(); err != nil || !h.closed {
		t.Fatalf("close: %v", err)
	}
	if _, err := age.Decrypt(ct, id); err == nil {
		t.Fatal("used a closed identity")
	}
}

func TestHybridHardwareIdentityRequiresValidKeys(t *testing.T) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := NewHybridHardwareIdentity(&softwareHardwareKey{PrivateKey: k}, make([]byte, mlkem.SeedSize)); err == nil {
		t.Fatal("accepted a non-P-256 hardware key")
	}
	p, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := NewHybridHardwareIdentity(&softwareHardwareKey{PrivateKey: p}, make([]byte, 10)); err == nil {
		t.Fatal("accepted a short ML-KEM seed")
	}
}

func TestManagerRefusesIdentityFromOlderEnbu(t *testing.T) {
	m := newManager(t)
	if err := os.MkdirAll(filepath.Dir(m.Path("o/r")), 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"version":1,"backend":"keyring","public_key":"age1old","reference":"old"}`)
	if err := os.WriteFile(m.Path("o/r"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := m.Create("o/r")
	var unavailableErr *UnavailableError
	if !errors.As(err, &unavailableErr) {
		t.Fatalf("Create() error = %v, want UnavailableError", err)
	}
	if !strings.Contains(err.Error(), m.Path("o/r")) {
		t.Fatalf("error %q does not name %s", err, m.Path("o/r"))
	}
	if after, _ := os.ReadFile(m.Path("o/r")); !bytes.Equal(after, legacy) {
		t.Fatal("replaced the older identity metadata")
	}
}

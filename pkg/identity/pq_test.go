package identity

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func newHybridHardware(t *testing.T) (Identity, *softwareHardwareKey) {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &softwareHardwareKey{PrivateKey: k}
	seed := make([]byte, mlkem.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	id, err := NewHybridHardwareIdentity(h, seed)
	if err != nil {
		t.Fatal(err)
	}
	return id, h
}

func TestHybridHardwareIdentityUsesBothKeys(t *testing.T) {
	id, h := newHybridHardware(t)
	defer func() { _ = id.Close() }()
	if !strings.HasPrefix(id.Recipient().String(), "age1tagpq1") || !age.IsPostQuantum(id.Recipient().String()) {
		t.Fatalf("unexpected recipient %.24s", id.Recipient().String())
	}
	soft, err := agecrypto.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipients := []string{id.Recipient().String(), soft.Recipient().String()}
	if !age.PostQuantum(recipients) {
		t.Fatal("tagged and software hybrid recipients must form a post-quantum set")
	}
	ct, err := age.EncryptForPublicKeys([]byte("hybrid"), recipients)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ct), "-> mlkem768p256tag ") {
		t.Fatal("no tagged hybrid stanza")
	}
	for _, i := range []agecrypto.Identity{id, soft} {
		out, err := age.Decrypt(ct, i)
		if err != nil || string(out) != "hybrid" {
			t.Fatalf("decrypt: %q %v", out, err)
		}
	}
	if h.calls != 1 {
		t.Fatalf("hardware ECDH calls = %d, want 1", h.calls)
	}

	// A different ML-KEM key with the same hardware key must not decrypt:
	// the hardware half alone is not enough.
	seed := make([]byte, mlkem.SeedSize)
	_, _ = rand.Read(seed)
	sameDevice, err := NewHybridHardwareIdentity(h, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(ct, sameDevice); err == nil {
		t.Fatal("decrypted without the matching ML-KEM key")
	}
}

func TestHybridHardwareIdentityRejectsClassicalAndMalformedStanzas(t *testing.T) {
	id, h := newHybridHardware(t)
	classical, err := NewHardwareIdentity(h)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := age.EncryptForPublicKeys([]byte("classical"), []string{classical.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(ct, id); err == nil {
		t.Fatal("hybrid identity unwrapped a classical p256tag stanza")
	}
	if _, err := id.Unwrap([]*agecrypto.Stanza{{Type: "mlkem768p256tag"}}); err == nil || errors.Is(err, agecrypto.ErrIncorrectIdentity) {
		t.Fatalf("malformed stanza: %v", err)
	}
	short := []*agecrypto.Stanza{{Type: "mlkem768p256tag", Args: []string{"AAAAAA", "AAAA"}, Body: make([]byte, 32)}}
	if _, err := id.Unwrap(short); err == nil {
		t.Fatal("accepted a short encapsulated key")
	}
	if err := id.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := id.Unwrap(nil); err == nil {
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

// TestHybridIdentityOnTPM pairs a real (virtual) TPM ECDH key with ML-KEM.
func TestHybridIdentityOnTPM(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	classical, _, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, mlkem.SeedSize)
	_, _ = rand.Read(seed)
	id, err := NewHybridHardwareIdentity(classical.(*taggedIdentity).key, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	ct, err := age.EncryptForPublicKeys([]byte("TPM + ML-KEM"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(ct, id)
	if err != nil || string(out) != "TPM + ML-KEM" {
		t.Fatalf("decrypt: %q %v", out, err)
	}
}

func TestManagerCreatesHybridKeyringIdentityByDefault(t *testing.T) {
	m := newManager(t)
	id, info, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if info.Backend != "keyring" || info.Algorithm != "MLKEM768-X25519" || !strings.HasPrefix(info.Recipient, "age1pq1") {
		t.Fatalf("info: %+v", info)
	}
	md, err := m.read("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(md.PublicKey), "SECRET") {
		t.Fatal("metadata holds the secret key")
	}
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	ct, err := age.EncryptForPublicKeys([]byte("pq"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := age.Decrypt(ct, loaded); err != nil || string(out) != "pq" {
		t.Fatalf("decrypt: %q %v", out, err)
	}

	// The keyring secret must be the algorithm the metadata names.
	md.Algorithm = "X25519"
	if err := saveMetadata(m.Path("o/r"), md); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("loaded a hybrid secret as X25519")
	}
}

func TestManagerClassicalModeKeepsX25519(t *testing.T) {
	m := newManager(t)
	m.Classical = true
	id, info, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if info.Algorithm != "X25519" || age.IsPostQuantum(info.Recipient) {
		t.Fatalf("info: %+v", info)
	}
	// A saved classical identity keeps loading after the flag is gone.
	m.Classical = false
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = loaded.Close()
}

func newTPMManager(t *testing.T) (*Manager, *TPMBackend) {
	t.Helper()
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	return &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: b}, b
}

func TestManagerCreatesHybridTPMIdentityWithSealedSeed(t *testing.T) {
	m, _ := newTPMManager(t)
	id, info, warning, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if info.Backend != "tpm" || info.Algorithm != "MLKEM768-P256" || !strings.HasPrefix(info.Recipient, "age1tagpq1") || warning != "" {
		t.Fatalf("info: %+v %q", info, warning)
	}
	ct, err := age.EncryptForPublicKeys([]byte("sealed"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	if out, err := age.Decrypt(ct, id); err != nil || string(out) != "sealed" {
		t.Fatalf("decrypt: %q %v", out, err)
	}
	_ = id.Close()
	md, err := m.read("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if len(md.TPMSealPublic) == 0 || len(md.TPMSealPrivate) == 0 || md.PQReference != "" {
		t.Fatal("the ML-KEM seed is not sealed by the TPM")
	}
	if len(m.Vault.(memoryVault)) != 0 {
		t.Fatal("a TPM identity put key material in the keyring")
	}
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := age.Decrypt(ct, loaded); err != nil || string(out) != "sealed" {
		t.Fatalf("decrypt after reload: %q %v", out, err)
	}
	_ = loaded.Close()

	// A sealed blob that does not match the template is refused.
	corrupt := *md
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](md.TPMSealPublic)
	if err != nil {
		t.Fatal(err)
	}
	contents, _ := pub.Contents()
	contents.ObjectAttributes.FixedTPM = false
	corrupt.TPMSealPublic = tpm2.Marshal(tpm2.New2B(*contents))
	if err := saveMetadata(m.Path("o/r"), &corrupt); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("loaded a seed object without fixedTPM")
	}
	corrupt = *md
	corrupt.TPMSealPrivate = append([]byte(nil), md.TPMSealPrivate...)
	corrupt.TPMSealPrivate[len(corrupt.TPMSealPrivate)-1] ^= 1
	if err := saveMetadata(m.Path("o/r"), &corrupt); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("loaded a corrupted sealed seed")
	}
}

func TestSealedSeedDoesNotUnsealOnAnotherTPM(t *testing.T) {
	m, _ := newTPMManager(t)
	id, _, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	md, err := m.read("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_, other := newTPMManager(t)
	if _, err := other.UnsealSeed(md); err == nil {
		t.Fatal("another TPM unsealed the seed")
	}
}

// fakeEnclave is a hardware backend that cannot seal, like the Secure Enclave.
type fakeEnclave struct{ keys map[string]*ecdh.PrivateKey }

func (f *fakeEnclave) Probe() Diagnosis { return Diagnosis{Backend: "secure-enclave", Available: true} }
func (f *fakeEnclave) Create() (Identity, *Metadata, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ref := "ref"
	f.keys[ref] = k
	id, err := NewHardwareIdentity(&softwareHardwareKey{PrivateKey: k})
	if err != nil {
		return nil, nil, err
	}
	return id, &Metadata{Version: 1, PublicInfo: PublicInfo{Backend: "secure-enclave", Algorithm: "P-256", Recipient: id.Recipient().String()},
		PublicKey: k.PublicKey().Bytes(), Reference: ref}, nil
}
func (f *fakeEnclave) Load(md *Metadata) (Identity, error) {
	if !hardwareAlgorithm(md.Algorithm) {
		return nil, errors.New("bad algorithm")
	}
	return NewHardwareIdentity(&softwareHardwareKey{PrivateKey: f.keys[md.Reference]})
}

func TestManagerKeepsUnsealableSeedInKeyring(t *testing.T) {
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: &fakeEnclave{keys: map[string]*ecdh.PrivateKey{}}}
	id, info, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if info.Algorithm != "MLKEM768-P256" || !strings.HasPrefix(info.Recipient, "age1tagpq1") {
		t.Fatalf("info: %+v", info)
	}
	md, _ := m.read("o/r")
	if md.PQReference == "" || len(m.Vault.(memoryVault)[md.PQReference]) != mlkem.SeedSize {
		t.Fatal("the ML-KEM seed is not in the keyring")
	}
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = loaded.Close()
	delete(m.Vault.(memoryVault), md.PQReference)
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("loaded a hybrid identity without its seed")
	}
}

// sealingEnclave seals the seed to its P-256 key, like the Secure Enclave
// backend on macOS.
type sealingEnclave struct{ fakeEnclave }

func (f *sealingEnclave) SealSeed(md *Metadata, seed []byte) error {
	pub, err := ecdh.P256().NewPublicKey(md.PublicKey)
	if err != nil {
		return err
	}
	md.EnclaveSeal, err = sealToECDH(pub, seed)
	return err
}

func (f *sealingEnclave) UnsealSeed(md *Metadata) ([]byte, error) {
	return openFromECDH(&softwareHardwareKey{PrivateKey: f.keys[md.Reference]}, md.EnclaveSeal)
}

func TestManagerSealsSeedToEnclaveKey(t *testing.T) {
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: &sealingEnclave{fakeEnclave{keys: map[string]*ecdh.PrivateKey{}}}}
	id, info, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if info.Algorithm != "MLKEM768-P256" {
		t.Fatalf("info: %+v", info)
	}
	md, _ := m.read("o/r")
	if md.PQReference != "" || len(m.Vault.(memoryVault)) != 0 || len(md.EnclaveSeal) == 0 {
		t.Fatalf("the ML-KEM seed is not sealed to the device key: %+v", md)
	}
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = loaded.Close()
	md.EnclaveSeal[len(md.EnclaveSeal)-1] ^= 1
	if err := saveMetadata(m.Path("o/r"), md); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("loaded a hybrid identity with a corrupted sealed seed")
	}
}

// blobEnclave keeps its keys by EnclaveKey, like the Secure Enclave backend,
// so a Manager that loses the field on save or read cannot load the identity.
type blobEnclave struct{ sealingEnclave }

func (f *blobEnclave) Create() (Identity, *Metadata, error) {
	id, md, err := f.fakeEnclave.Create()
	if err != nil {
		return nil, nil, err
	}
	blob := make([]byte, 16)
	_, _ = rand.Read(blob)
	f.keys[string(blob)] = f.keys[md.Reference]
	delete(f.keys, md.Reference)
	md.Reference, md.EnclaveKey = "", blob
	return id, md, nil
}

func (f *blobEnclave) key(md *Metadata) (*ecdh.PrivateKey, error) {
	k, ok := f.keys[string(md.EnclaveKey)]
	if len(md.EnclaveKey) == 0 || !ok {
		return nil, errors.New("no Secure Enclave key data")
	}
	return k, nil
}

func (f *blobEnclave) Load(md *Metadata) (Identity, error) {
	k, err := f.key(md)
	if err != nil {
		return nil, err
	}
	return NewHardwareIdentity(&softwareHardwareKey{PrivateKey: k})
}

func (f *blobEnclave) UnsealSeed(md *Metadata) ([]byte, error) {
	k, err := f.key(md)
	if err != nil {
		return nil, err
	}
	return openFromECDH(&softwareHardwareKey{PrivateKey: k}, md.EnclaveSeal)
}

func TestManagerLoadsIdentityFromEnclaveKey(t *testing.T) {
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: &blobEnclave{sealingEnclave{fakeEnclave{keys: map[string]*ecdh.PrivateKey{}}}}}
	id, info, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := age.EncryptForPublicKeys([]byte("blob"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	md, err := m.read("o/r")
	if err != nil || len(md.EnclaveKey) == 0 || len(md.EnclaveSeal) == 0 {
		t.Fatalf("saved metadata lost the Secure Enclave fields: %+v %v", md, err)
	}
	loaded, err := m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	if out, err := age.Decrypt(ct, loaded); err != nil || string(out) != "blob" {
		t.Fatalf("decrypt: %q %v", out, err)
	}
	md.EnclaveKey = nil
	if err := saveMetadata(m.Path("o/r"), md); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load("o/r"); err == nil {
		t.Fatal("loaded an identity without its Secure Enclave key data")
	}
}

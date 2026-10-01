package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
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
func (v memoryVault) Delete(_, key string) error { delete(v, key); return nil }

type fakeHardware struct {
	available   bool
	createError error
	creates     int
	loads       int
}

func (h *fakeHardware) Probe() Diagnosis {
	return Diagnosis{Backend: "tpm", Available: h.available, Reason: "no TPM device"}
}
func (h *fakeHardware) Create() (Identity, *Metadata, error) {
	h.creates++
	return nil, nil, h.createError
}
func (h *fakeHardware) Load(*Metadata) (Identity, error) {
	h.loads++
	return nil, errors.New("broken hardware key")
}

func newManager(t *testing.T) *Manager {
	t.Helper()
	return &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: &fakeHardware{}}
}

func TestManagerFallbackReuseAndMetadata(t *testing.T) {
	m := newManager(t)
	id, info, warning, err := m.Create("Owner", "Repo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	if info.Backend != "keyring" || !strings.Contains(warning, "no TPM device") {
		t.Fatalf("%+v %q", info, warning)
	}
	id2, info2, warning, err := m.Create("owner", "repo")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id2.Close() }()
	if info2.Recipient != info.Recipient || info2.Created || !info.Created || warning != "" {
		t.Fatalf("did not reuse: %+v %q", info2, warning)
	}
	md, err := m.read("owner", "repo")
	if err != nil {
		t.Fatal(err)
	}
	if md.Version != 1 || md.Reference == "" || strings.Contains(string(md.PublicKey), "SECRET") {
		t.Fatalf("invalid metadata: %+v", md)
	}
	if stat, err := os.Stat(m.Path("owner", "repo")); err != nil || stat.Mode().Perm()&0o077 != 0 {
		t.Fatalf("metadata permissions: %v %v", stat, err)
	}
	ciphertext, err := age.EncryptForPublicKeys([]byte("secret"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(ciphertext, id2)
	if err != nil || string(out) != "secret" {
		t.Fatalf("reload: %q %v", out, err)
	}
	if _, err := m.Info("owner", "repo"); err != nil {
		t.Fatal(err)
	}
}

func TestManagerNeverReplacesSavedOrPartiallyCreatedKey(t *testing.T) {
	for _, mode := range []string{"auto", "hardware"} {
		t.Run(mode, func(t *testing.T) {
			m := newManager(t)
			m.Mode = mode
			h := &fakeHardware{available: true, createError: errors.New("creation failed")}
			m.Hardware = h
			if _, _, _, err := m.Create("o", "r"); err == nil {
				t.Fatal("silently fell back after create failure")
			}
			if len(m.Vault.(memoryVault)) != 0 {
				t.Fatal("created fallback key")
			}
			md := &Metadata{Version: 1, PublicInfo: PublicInfo{Backend: "tpm", Algorithm: "P-256", Recipient: "saved"}, PublicKey: []byte{1}}
			if err := saveMetadata(m.Path("o", "r"), md); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := m.Create("o", "r"); err == nil {
				t.Fatal("silently replaced broken saved key")
			}
			if h.creates != 1 || h.loads != 1 {
				t.Fatalf("calls: %+v", h)
			}
		})
	}
}

func TestManagerDetectsTampering(t *testing.T) {
	for _, field := range []string{"version", "recipient", "public_key", "reference", "secret", "empty"} {
		t.Run(field, func(t *testing.T) {
			m := newManager(t)
			id, _, _, err := m.Create("o", "r")
			if err != nil {
				t.Fatal(err)
			}
			_ = id.Close()
			md, err := m.read("o", "r")
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "version":
				md.Version = 2
			case "recipient":
				md.Recipient = "age1wrong"
			case "public_key":
				md.PublicKey = []byte("wrong")
			case "reference":
				md.Reference = "missing"
			case "secret":
				m.Vault.(memoryVault)[md.Reference] = []byte("corrupt")
			case "empty":
				md.PublicKey = nil
			}
			if err := saveMetadata(m.Path("o", "r"), md); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(m.Path("o", "r"))
			if _, _, _, err := m.Create("o", "r"); err == nil {
				t.Fatal("accepted tampered identity")
			}
			after, _ := os.ReadFile(m.Path("o", "r"))
			if !bytes.Equal(before, after) {
				t.Fatal("replaced saved metadata")
			}
		})
	}
}

func TestBackendSelectionAndDoctor(t *testing.T) {
	m := newManager(t)
	m.Mode = "hardware"
	if _, _, _, err := m.Create("o", "r"); err == nil {
		t.Fatal("hardware mode fell back")
	}
	m.Mode = "unknown"
	if _, _, _, err := m.Create("o", "r"); err == nil {
		t.Fatal("accepted invalid mode")
	}
	m.Mode = "keyring"
	id, _, warning, err := m.Create("o", "r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	if warning != "" {
		t.Fatalf("explicit keyring warning: %s", warning)
	}
	m.Mode = "hardware"
	if _, err := m.Load("o", "r"); err == nil {
		t.Fatal("hardware mode loaded keyring identity")
	}
	d := m.Doctor()
	if d.Available || !d.FallbackAvailable {
		t.Fatalf("doctor: %+v", d)
	}
	if m.Hardware.(*fakeHardware).creates != 0 {
		t.Fatal("doctor created a key")
	}
}

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

func TestMixedRecipientsAndMalformedStanzas(t *testing.T) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &softwareHardwareKey{PrivateKey: k}
	id, err := NewHardwareIdentity(h)
	if err != nil {
		t.Fatal(err)
	}
	x, err := agecrypto.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := age.EncryptForPublicKeys([]byte("mixed"), []string{id.Recipient().String(), x.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []agecrypto.Identity{id, x} {
		out, err := age.Decrypt(ct, i)
		if err != nil || string(out) != "mixed" {
			t.Fatalf("mixed decryption: %q %v", out, err)
		}
	}
	if _, err := id.Unwrap([]*agecrypto.Stanza{{Type: "p256tag"}}); err == nil {
		t.Fatal("accepted malformed stanza")
	}
	if _, err := id.Unwrap([]*agecrypto.Stanza{{Type: "X25519"}}); !errors.Is(err, agecrypto.ErrIncorrectIdentity) {
		t.Fatal(err)
	}
	if err := id.Close(); err != nil {
		t.Fatal(err)
	}
	if !h.closed {
		t.Fatal("hardware key leaked")
	}
	if _, err := age.Decrypt(ct, id); err == nil {
		t.Fatal("used closed hardware key")
	}
}

func TestMetadataHasNoPrivateKey(t *testing.T) {
	m := newManager(t)
	id, _, _, err := m.Create("o", "r")
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	b, err := os.ReadFile(m.Path("o", "r"))
	if err != nil {
		t.Fatal(err)
	}
	var md map[string]any
	if err := json.Unmarshal(b, &md); err != nil {
		t.Fatal(err)
	}
	for _, secret := range m.Vault.(memoryVault) {
		if bytes.Contains(b, secret) {
			t.Fatal("private key stored in metadata")
		}
	}
}

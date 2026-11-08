package identity

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"math/big"
	"strings"
	"sync"
	"testing"

	vtpm "github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type virtualTransport struct{ t *vtpm.TPM }

func (t *virtualTransport) Send(b []byte) ([]byte, error) { return t.t.Execute(b), nil }
func (t *virtualTransport) Close() error                  { return nil }

func newVirtualTPM(t *testing.T) *vtpm.TPM {
	t.Helper()
	v := vtpm.New()
	if _, err := (tpm2.Startup{StartupType: tpm2.TPMSUClear}).Execute(&virtualTransport{v}); err != nil {
		t.Fatal(err)
	}
	return v
}

func newTPMBackend(t *testing.T) *TPMBackend {
	t.Helper()
	return &TPMBackend{Device: "test", plainSessions: true, Open: virtualOpener(newVirtualTPM(t))}
}

func virtualOpener(v interface{ Execute([]byte) []byte }) func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) { return &funcTransport{v.Execute}, nil }
}

type funcTransport struct{ execute func([]byte) []byte }

func (t *funcTransport) Send(b []byte) ([]byte, error) { return t.execute(b), nil }
func (t *funcTransport) Close() error                  { return nil }

func newTPMDevice(t *testing.T, b *TPMBackend) (*Device, *Metadata) {
	t.Helper()
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: b}
	d, _, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	md, err := m.read("o/r")
	if err != nil {
		t.Fatal(err)
	}
	return d, md
}

func TestTPMRoundTripAndRestart(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", plainSessions: true, Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	if d := b.Probe(); !d.Available {
		t.Fatalf("probe: %+v", d)
	}
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: b}
	d, info, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if info.Backend != "tpm" || info.Algorithm != "MLKEM768-P256" || !strings.HasPrefix(info.Recipient, "age1tagpq1") {
		t.Fatalf("info: %+v", info)
	}
	ciphertext, err := age.EncryptForPublicKeys([]byte("TPM secret"), []string{info.Recipient})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, d, info.Recipient)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	// A new TPM instance restores only durable state, not loaded child objects.
	snapshot := v.Snapshot()
	v = vtpm.New()
	if err := v.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	d, err = m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if out, err := age.Decrypt(ciphertext, d.Identity); err != nil || string(out) != "TPM secret" {
		t.Fatalf("decrypt after restart: %s %v", out, err)
	}
	if string(d.Signer.Public().DeviceID()) != info.DeviceID {
		t.Fatal("reloaded signing key changed")
	}
}

func TestTPMLoadChecksItsMetadata(t *testing.T) {
	b := newTPMBackend(t)
	d, md := newTPMDevice(t, b)
	_ = d.Close()
	flip := func(b []byte) []byte { b = bytes.Clone(b); b[len(b)-1] ^= 1; return b }
	for name, damage := range map[string]func(*TPMKeys){
		"tampered public":   func(k *TPMKeys) { k.ECDH.Public = flip(k.ECDH.Public) },
		"tampered private":  func(k *TPMKeys) { k.Sign.Private = flip(k.Sign.Private) },
		"tampered name":     func(k *TPMKeys) { k.ECDH.Name = []byte("bad") },
		"swapped keys":      func(k *TPMKeys) { k.ECDH, k.Sign = k.Sign, k.ECDH },
		"signer as ECDH":    func(k *TPMKeys) { k.ECDH = k.Sign },
		"ECDH as signer":    func(k *TPMKeys) { k.Sign = k.ECDH },
		"another primary":   func(k *TPMKeys) { k.Parent = []byte("another primary") },
		"no pinned primary": func(k *TPMKeys) { k.Parent = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *md
			keys := *md.TPM
			damage(&keys)
			bad.TPM = &keys
			if key, signer, err := b.Load(&bad); err == nil {
				_ = key.Close()
				_ = signer.Close()
				t.Fatal("damaged metadata loaded")
			}
			if b.conn != nil {
				t.Fatal("a refused key left the connection open")
			}
		})
	}
	if _, _, err := b.Load(&Metadata{Backend: "tpm"}); err == nil {
		t.Fatal("loaded metadata without TPM keys")
	}
}

func TestTPMSignaturesAreLowSAndStopAfterClose(t *testing.T) {
	d, _ := newTPMDevice(t, newTPMBackend(t))
	s := d.Signer
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	for i := 0; i < 8; i++ {
		sig, err := s.Sign(signing.DomainState, []byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if new(big.Int).SetBytes(sig[32:]).Cmp(half) > 0 {
			t.Fatalf("signature %d is not low-S", i)
		}
	}
	if _, err := s.Sign("bad\x00domain", []byte("b")); err == nil {
		t.Fatal("a domain with the separator byte was signed")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(signing.DomainState, []byte("b")); err == nil {
		t.Fatal("a closed signer signed")
	}
}

// countingTPM counts the TPM opens and the CreatePrimary commands of a backend.
type countingTPM struct {
	mu        sync.Mutex
	opens     int
	primaries int
	open      int // connections not closed yet
}

func (c *countingTPM) backend(t *testing.T) *TPMBackend {
	t.Helper()
	v := newVirtualTPM(t)
	return &TPMBackend{Device: "test", plainSessions: true, Open: func() (transport.TPMCloser, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.opens++
		c.open++
		return &countedTransport{counter: c, inner: &virtualTransport{v}}, nil
	}}
}

type countedTransport struct {
	counter *countingTPM
	inner   transport.TPMCloser
}

func (t *countedTransport) Send(cmd []byte) ([]byte, error) {
	if len(cmd) >= 10 && tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10])) == tpm2.TPMCCCreatePrimary {
		t.counter.mu.Lock()
		t.counter.primaries++
		t.counter.mu.Unlock()
	}
	return t.inner.Send(cmd)
}

func (t *countedTransport) Close() error {
	t.counter.mu.Lock()
	t.counter.open--
	t.counter.mu.Unlock()
	return t.inner.Close()
}

// TestTPMKeysShareOneConnection checks that loading a device opens the TPM
// and creates the storage primary once, and that closing every key releases it.
func TestTPMKeysShareOneConnection(t *testing.T) {
	counter := &countingTPM{}
	m := &Manager{Dir: t.TempDir(), Vault: memoryVault{}, Hardware: counter.backend(t)}
	d, _, _, err := m.Create("o/r")
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if counter.open != 0 {
		t.Fatalf("%d TPM connections left open after closing every key", counter.open)
	}
	counter.opens, counter.primaries = 0, 0
	d, err = m.Load("o/r")
	if err != nil {
		t.Fatal(err)
	}
	if counter.opens != 1 || counter.primaries != 1 {
		t.Fatalf("loading a device: %d opens and %d primaries, want 1 and 1", counter.opens, counter.primaries)
	}
	if err := d.Identity.Close(); err != nil {
		t.Fatal(err)
	}
	// The signer still holds the connection, so it keeps working.
	if _, err := d.Signer.Sign(signing.DomainState, []byte("y")); err != nil {
		t.Fatalf("signer after the identity closed: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if counter.open != 0 {
		t.Fatalf("%d TPM connections left open", counter.open)
	}
}

// TestTPMKeysUseOneConnectionConcurrently runs ECDH and signatures from
// several goroutines over the shared connection; the race detector and the
// TPM's session checks catch interleaved commands.
func TestTPMKeysUseOneConnectionConcurrently(t *testing.T) {
	b := (&countingTPM{}).backend(t)
	key, s, err := b.Create(&Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = key.Close(); _ = s.Close() }()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := key.ECDH(key.PublicKey()); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := s.Sign(signing.DomainState, []byte("x")); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestTPMPrimaryNameMustMatchItsPublicArea feeds verifyPrimary the genuine
// Name of one TPM's primary with the public area of another, as an interposer
// that wants the session salt would, and a public area off the template.
func TestTPMPrimaryNameMustMatchItsPublicArea(t *testing.T) {
	primary := func() (*tpm2.TPMTPublic, tpm2.TPM2BName) {
		t.Helper()
		v := newVirtualTPM(t)
		p, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16)},
			InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(&virtualTransport{v})
		if err != nil {
			t.Fatal(err)
		}
		pub, err := p.OutPublic.Contents()
		if err != nil {
			t.Fatal(err)
		}
		return pub, p.Name
	}
	genuine, genuineName := primary()
	if err := verifyPrimary(genuine, genuineName); err != nil {
		t.Fatalf("genuine primary refused: %v", err)
	}
	other, _ := primary()
	if err := verifyPrimary(other, genuineName); err == nil {
		t.Fatal("accepted another public area under the genuine Name")
	}
	offTemplate := *genuine
	offTemplate.ObjectAttributes.Restricted = false
	name, err := tpm2.ObjectName(&offTemplate)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrimary(&offTemplate, *name); err == nil {
		t.Fatal("accepted a primary off the storage template")
	}
}

package identity

import (
	"testing"

	vtpm "github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
	"github.com/enbu-net/enbu/pkg/age"
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

func TestTPMRoundTripAndRestart(t *testing.T) {
	v := newVirtualTPM(t)
	b := &TPMBackend{Device: "test", Open: func() (transport.TPMCloser, error) { return &virtualTransport{v}, nil }}
	if d := b.Probe(); !d.Available {
		t.Fatalf("probe: %+v", d)
	}
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := age.EncryptForPublicKeys([]byte("TPM secret"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(ciphertext, id)
	if err != nil || string(out) != "TPM secret" {
		t.Fatalf("decrypt: %s %v", out, err)
	}
	if err := id.Close(); err != nil {
		t.Fatal(err)
	}
	// A new TPM instance restores only durable state, not loaded child objects.
	snapshot := v.Snapshot()
	v = vtpm.New()
	if err := v.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	id, err = b.Load(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = id.Close() }()
	out, err = age.Decrypt(ciphertext, id)
	if err != nil || string(out) != "TPM secret" {
		t.Fatalf("decrypt after restart: %s %v", out, err)
	}
	corrupt := *md
	corrupt.TPMName = []byte("bad name")
	if _, err := b.Load(&corrupt); err == nil {
		t.Fatal("accepted corrupt Name")
	}
	corrupt = *md
	corrupt.TPMPrivate = append([]byte(nil), md.TPMPrivate...)
	corrupt.TPMPrivate[len(corrupt.TPMPrivate)-1] ^= 1
	if _, err := b.Load(&corrupt); err == nil {
		t.Fatal("accepted corrupt child blob")
	}
}

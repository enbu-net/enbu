//go:build linux || windows

package identity

import (
	"os"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
)

func TestTPMNativeLifecycle(t *testing.T) {
	if os.Getenv("ENBU_TEST_NATIVE_IDENTITY") != "1" {
		t.Skip("set ENBU_TEST_NATIVE_IDENTITY=1 on a TPM 2.0 device")
	}
	b := platformHardware()
	if d := b.Probe(); !d.Available {
		t.Fatalf("native hardware unavailable: %+v", d)
	}
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := age.EncryptForPublicKeys([]byte("native TPM"), []string{id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	_ = id.Close()
	loaded, err := b.Load(md)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	out, err := age.Decrypt(ct, loaded)
	if err != nil || string(out) != "native TPM" {
		t.Fatalf("native decrypt: %q %v", out, err)
	}
}

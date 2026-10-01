//go:build darwin

package identity

import (
	"bytes"
	"os"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
)

func TestSecureEnclaveNativeLifecycle(t *testing.T) {
	if os.Getenv("ENBU_TEST_NATIVE_IDENTITY") != "1" {
		t.Skip("set ENBU_TEST_NATIVE_IDENTITY=1 on a Secure Enclave device")
	}
	b := &enclaveBackend{}
	if d := b.Probe(); !d.Available {
		t.Fatalf("native hardware unavailable: %+v", d)
	}
	id, md, err := b.Create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Delete(md) })
	ct, err := age.EncryptForPublicKeys([]byte("native enclave"), []string{id.Recipient().String()})
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
	if err != nil || !bytes.Equal(out, []byte("native enclave")) {
		t.Fatalf("native decrypt: %q %v", out, err)
	}
}

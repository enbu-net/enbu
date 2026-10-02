//go:build darwin

package identity

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/age"
)

func TestSecureEnclaveKeychainPreflight(t *testing.T) {
	a, err := loadSecurity()
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int32{0, -25300, -34018, -25308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			api := *a
			api.itemCopy = func(q uintptr, ref *uintptr) int32 {
				if !api.equal(api.dictGet(q, api.constant("kSecUseDataProtectionKeychain")), api.constant("kCFBooleanTrue")) {
					t.Fatal("preflight queried the file-based Keychain")
				}
				if !api.equal(api.dictGet(q, api.constant("kSecUseAuthenticationUI")), api.constant("kSecUseAuthenticationUIFail")) {
					t.Fatal("preflight may prompt for authentication")
				}
				return status
			}
			api.keyCreate = func(uintptr, *uintptr) uintptr {
				t.Fatal("preflight attempted to create a key")
				return 0
			}
			err := api.probeKeychainAccess()
			if status == 0 || status == -25300 {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("Keychain failure was not reported: %v", err)
			}
		})
	}
}

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

//go:build identitye2e && (linux || windows)

package identitye2e

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/identity"
)

// This opt-in test builds the production CLI without identitytest. It uses the
// host TPM through /dev/tpmrm0 or Windows TBS; only the OCI/GitHub HTTP services
// are local fixtures. No persistent TPM handles or real repository data are used.
func TestNativeTPMCLI(t *testing.T) {
	if os.Getenv("ENBU_TEST_NATIVE_IDENTITY") != "1" {
		t.Skip("set ENBU_TEST_NATIVE_IDENTITY=1 with access to a real TPM 2.0")
	}
	registry := httptest.NewServer(newRegistry())
	defer registry.Close()
	host := "localhost:" + strings.Split(registry.Listener.Addr().String(), ":")[1]
	h := newHarness(t, buildCLI(t, host, false), "hardware")

	d := h.run("doctor")
	if d["backend"] != "tpm" || d["available"] != true || d["device"] == "test-only vTPM" {
		t.Fatalf("native TPM unavailable: %+v", d)
	}
	t.Logf("native TPM available: %v", d["device"])
	initialized := h.run("init")
	recipient, ok := initialized["public_key"].(string)
	if !ok || !strings.HasPrefix(recipient, "age1tag1") || initialized["key_created"] != true {
		t.Fatalf("init did not create a tagged TPM Identity: %+v", initialized)
	}
	shown := h.run("identity", "show")
	if shown["backend"] != "tpm" || shown["algorithm"] != "P-256" || shown["recipient"] != recipient {
		t.Fatalf("init did not save a native TPM Identity: %+v", shown)
	}
	m := &identity.Manager{Dir: filepath.Join(h.env["XDG_DATA_HOME"], "enbu", "identities")}
	metadataPath := m.Path(h.workspaceID)
	saved, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("init: created and registered native TPM recipient")

	h.run("add", "DATABASE_URL", "first")
	assertSecret(t, h.run("pull"), "first")
	t.Log("add/pull: native TPM decryption succeeded in a new CLI process")
	h.run("edit", "DATABASE_URL", "second")

	// Verify that sync encrypts for both the hardware Identity and an ordinary
	// X25519 recipient, and that both recover the actual saved secret value.
	x, err := agecrypto.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	approveX25519(t, h, x)
	h.run("sync")
	assertSecret(t, h.run("pull"), "second")
	plaintext := decryptCurrent(t, h, x)
	secrets, err := bundle.Unmarshal(plaintext)
	if err != nil || secrets["DATABASE_URL"] != "second" {
		t.Fatalf("software recipient recovered wrong bundle: %v %v", secrets, err)
	}
	t.Log("sync: both native TPM and X25519 recipients decrypted the saved bundle")

	diff := h.run("history", "diff", "1", "2")
	modified, ok := diff["modified"].([]any)
	if !ok || len(modified) != 1 || modified[0] != "DATABASE_URL" {
		t.Fatalf("history decryption did not recover the expected change: %+v", diff)
	}
	h.run("history", "restore", "1")
	assertSecret(t, h.run("pull"), "first")
	t.Log("history: decrypted previous snapshots and restored the original value")

	// Each h.run starts and exits a separate production CLI process. Repeated
	// initialization must load the same blob and register the same recipient.
	again := h.run("init")
	if again["public_key"] != recipient || again["key_created"] != false {
		t.Fatalf("restarted init replaced the Identity: %+v", again)
	}
	if shown := h.run("identity", "show"); shown["recipient"] != recipient {
		t.Fatalf("recipient changed after CLI restart: %+v", shown)
	}
	after, err := os.ReadFile(metadataPath)
	if err != nil || !bytes.Equal(saved, after) {
		t.Fatalf("saved TPM metadata changed across CLI processes: %v", err)
	}
	t.Log("restart: same recipient and TPM blobs reloaded; metadata unchanged")
}

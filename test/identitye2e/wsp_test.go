//go:build identitye2e

package identitye2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"
	"time"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

func openOCIStore(t *testing.T, h *cliHarness) *storage.Store {
	t.Helper()
	store, err := storage.NewOCI(strings.TrimPrefix(h.storageURL, "oci://"), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// approveX25519 makes x a member through the production CLI: it is another
// device, with its own software signing key, that leaves a signed join request
// in the workspace's storage; h's admin then approves it from the list.
func approveX25519(t *testing.T, h *cliHarness, x *agecrypto.X25519Identity) {
	t.Helper()
	ctx := context.Background()
	store := openOCIStore(t, h)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := signing.NewEd25519Signer(key)
	request, err := wsp.NewJoinRequest(h.workspaceID, x.Recipient().String(), time.Now(), signer)
	if err != nil {
		t.Fatal(err)
	}
	d, err := store.Blobs.Put(ctx, bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	device := signer.Public().DeviceID()
	if err := store.Refs.Put(ctx, wsp.JoinRequestRef(device), d, ""); err != nil {
		t.Fatal(err)
	}
	approved := h.run("member", "approve", "--device", string(device))
	if approved["action"] != "approve" {
		t.Fatalf("approve: %+v", approved)
	}
}

// decryptCurrent reads the current secrets state the way a client does, but as
// the holder of x: it verifies the Control chain and the SignedState before
// decrypting. It fails if x is not a recipient.
func decryptCurrent(t *testing.T, h *cliHarness, x *agecrypto.X25519Identity) []byte {
	t.Helper()
	ctx := context.Background()
	store := openOCIStore(t, h)
	cfg, err := config.LoadProjectFrom(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	head, err := wsp.LoadControl(ctx, store, h.workspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	read := func(d digest.Digest) []byte {
		rc, err := store.Blobs.Open(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ref, _, err := store.Refs.Get(ctx, "secrets-default")
	if err != nil {
		t.Fatal(err)
	}
	state, err := wsp.VerifyState(head.Verified, h.workspaceID, "secrets/default", read(ref))
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	plaintext, err := age.Decrypt(read(state.Ciphertext), x)
	if err != nil {
		t.Fatalf("not a recipient: %v", err)
	}
	return plaintext
}

//go:build identitye2e

package identitye2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

func openOCIStore(t *testing.T, h *cliHarness) storage.Store {
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
	if _, err := wsp.PublishJoinRequest(ctx, store, request); err != nil {
		t.Fatal(err)
	}
	device := signer.Public().DeviceID()
	approved := h.run("member", "approve", "--device", string(device))
	if approved["action"] != "approve" {
		t.Fatalf("approve: %+v", approved)
	}
}

// decryptCurrent reads the current secrets state the way a client does, but as
// the holder of x: it verifies the Control DAG and the signed revisions before
// decrypting. It fails if x is not a recipient.
func decryptCurrent(t *testing.T, h *cliHarness, x *agecrypto.X25519Identity) []byte {
	t.Helper()
	ctx := context.Background()
	store := openOCIStore(t, h)
	cfg, err := config.LoadProjectFrom(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	view, err := wsp.LoadControl(ctx, store, h.workspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	sv, err := wsp.LoadStates(ctx, store, view, h.workspaceID, cfg.Resource("default"))
	if err != nil || len(sv.Heads) != 1 {
		t.Fatalf("states: %v (%d heads)", err, len(sv.Heads))
	}
	state := sv.Heads[0]
	o, err := store.Fetch(ctx, storage.KindState, state.Scope(), state.Digest)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := age.Decrypt(o.Cipher, x)
	if err != nil {
		t.Fatalf("not a recipient: %v", err)
	}
	return plaintext
}

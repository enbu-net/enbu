package app

import (
	"bytes"
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// stateBlob returns the stored bytes of a SignedState for ciphertext, signed by
// this app's own device. It is the successor of the state currently at ref in
// store, or a first state if there is none. Tests use it to put arbitrary
// ciphertext behind a ref the way a legitimate writer would.
func stateBlob(t *testing.T, a *App, store *storage.Store, ref, env string, ciphertext []byte) []byte {
	t.Helper()
	ctx := context.Background()
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	head, err := wsp.LoadControl(ctx, store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := a.Identities.LoadSigner(cfg.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	ct, err := store.Blobs.Put(ctx, bytes.NewReader(ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	st := wsp.State{Workspace: cfg.WorkspaceID, Resource: secretsResource(env), Sequence: 1,
		ControlGeneration: head.Generation, Control: head.Digest, Ciphertext: ct, Author: signer.Public().DeviceID()}
	if d, _, err := store.Refs.Get(ctx, ref); err == nil {
		prev, err := readBlob(ctx, store, d)
		if err != nil {
			t.Fatal(err)
		}
		cur, err := wsp.VerifyState(head.Verified, cfg.WorkspaceID, st.Resource, prev)
		if err != nil {
			t.Fatal(err)
		}
		st.Sequence, st.Previous = cur.Sequence+1, cur.Digest
	}
	blob, err := wsp.SignState(st, signer)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

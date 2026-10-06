package app

import (
	"bytes"
	"context"
	"testing"

	apptest "github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
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

var bg = context.Background()

// newDevice is another machine of the same repository: it shares the storage
// and the committed enbu.toml (including control_genesis) but has its own keys
// and its own local checkpoints.
func newDevice(t *testing.T, alice *App) *App {
	t.Helper()
	b := &App{Storage: alice.Storage, Identities: newMemKeyStore(), CheckpointDir: t.TempDir(), RepositoryDir: t.TempDir(),
		TokenProvider: &staticTokenProvider{token: "tok", username: "bob"}, RepoDetector: &staticRepoDetector{owner: "owner", repo: "repo"}}
	cfg, err := alice.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SaveProjectTo(b.RepositoryDir, cfg); err != nil {
		t.Fatal(err)
	}
	return b
}

// newAlice is the founder: a workspace with one admin and one secret.
func newAlice(t *testing.T) *App {
	t.Helper()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "v1"})
	// A no-op when the workspace was initialized through the real flow.
	if err := apptest.Control(bg, a.Storage, a.RepositoryDir, a.Identities); err != nil {
		t.Fatal(err)
	}
	return a
}

type joined struct{ DeviceID, Fingerprint string }

// requestJoin makes d ask to join the workspace, as `enbu init` does for a
// device that is not a member.
func requestJoin(t *testing.T, d *App) joined {
	t.Helper()
	id, err := apptest.JoinRequest(bg, d.Storage, mustWorkspace(t, d), d.Identities)
	if err != nil {
		t.Fatal(err)
	}
	return joined{DeviceID: id, Fingerprint: signing.DeviceID(id).Fingerprint()}
}

func mustWorkspace(t *testing.T, a *App) string {
	t.Helper()
	id, err := a.WorkspaceID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// signAsOutsider builds a state with the attacker's own valid signature.
func signAsOutsider(t *testing.T, alice, attacker *App, env string, ciphertext []byte) []byte {
	t.Helper()
	cfg, _ := attacker.loadProject()
	signer, err := attacker.Identities.LoadSigner(cfg.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ct, err := alice.Storage.Blobs.Put(bg, bytes.NewReader(ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	// A first state for env with the attacker's own valid signature; only the
	// author is wrong, so a rejection can only be about who signed it.
	blob, err := wsp.SignState(wsp.State{Workspace: cfg.WorkspaceID, Resource: secretsResource(env), Sequence: 1,
		ControlGeneration: s.head.Generation, Control: s.head.Digest, Ciphertext: ct, Author: signer.Public().DeviceID()}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

package app

import (
	"context"
	"testing"

	apptest "github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/fxamacker/cbor/v2"
	"github.com/opencontainers/go-digest"
)

// publishRevision signs a State as author and publishes it with the given
// ciphertext bytes, the way a writer would. control names the Control revision
// the author claims to have seen. It returns the revision.
func publishRevision(t *testing.T, store storage.Store, author *App, workspace, resource string, control digest.Digest, ciphertext []byte, parents ...digest.Digest) digest.Digest {
	t.Helper()
	return publishRevisionAt(t, store, author, workspace, resource, control, ciphertext, 1700000000, parents...)
}

// publishRevisionAt is publishRevision with a fixed creation time, so history
// ordering does not depend on the wall clock.
func publishRevisionAt(t *testing.T, store storage.Store, author *App, workspace, resource string, control digest.Digest, ciphertext []byte, createdAt int64, parents ...digest.Digest) digest.Digest {
	t.Helper()
	return publishRevisionOp(t, store, author, workspace, resource, control, ciphertext, createdAt, wsp.OpWrite, parents...)
}

// publishRevisionOp is publishRevisionAt for a revision of the kind op.
func publishRevisionOp(t *testing.T, store storage.Store, author *App, workspace, resource string, control digest.Digest, ciphertext []byte, createdAt int64, op string, parents ...digest.Digest) digest.Digest {
	t.Helper()
	signer, err := loadSigner(author, workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	st := wsp.State{Workspace: workspace, Resource: resource, Parents: parents, Generation: generationAbove(store, workspace, resource, parents),
		Op: op, Control: control, Ciphertext: digest.FromBytes(ciphertext), Author: signer.Public().DeviceID(), CreatedAt: createdAt}
	blob, err := wsp.SignState(st, signer)
	if err != nil {
		t.Fatal(err)
	}
	rev := digest.FromBytes(blob)
	if err := store.Publish(bg, storage.Object{Kind: storage.KindState, Scope: st.Scope(), Rev: rev, Head: blob, Blobs: [][]byte{ciphertext}}); err != nil {
		t.Fatal(err)
	}
	return rev
}

// generationAbove is the Generation of a revision on top of parents, as far as
// storage still holds them; a parent it does not hold or cannot decode counts
// as generation 1.
func generationAbove(store storage.Store, workspace, resource string, parents []digest.Digest) uint64 {
	var top uint64
	for _, p := range parents {
		gen := uint64(1)
		head, err := store.FetchHead(bg, storage.KindState, storage.StateScope(workspace, resource), p)
		var signed wsp.Signed
		if err == nil {
			signed, err = wsp.DecodeSigned(head)
		}
		var st wsp.State
		if err == nil && cbor.Unmarshal(signed.Body, &st) == nil {
			gen = max(st.Generation, 1)
		}
		top = max(top, gen)
	}
	return top + 1
}

// revisionsOf lists the revisions storage shows for env.
func revisionsOf(t *testing.T, a *App, env string) []digest.Digest {
	t.Helper()
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	revs, err := a.Storage.Discover(bg, storage.KindState, storage.StateScope(cfg.WorkspaceID, cfg.Resource(env)))
	if err != nil {
		t.Fatal(err)
	}
	return revs
}

var bg = context.Background()

// newDevice is another machine of the same repository: it shares the storage
// and the committed enbu.toml (including control_genesis) but has its own keys
// and its own local checkpoints.
func newDevice(t *testing.T, alice *App) *App {
	t.Helper()
	b := &App{Storage: alice.Storage, Identities: &apptest.Identities{}, CheckpointDir: t.TempDir(), RepositoryDir: t.TempDir(),
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
	id, err := apptest.JoinRequest(bg, d.Storage, mustWorkspace(t, d), d.Identities, d.clock())
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

// loadSigner returns the saved signing key of a's device in workspace.
func loadSigner(a *App, workspace string) (signing.Signer, error) {
	d, err := a.Identities.Load(workspace)
	if err != nil {
		return nil, err
	}
	_ = d.Identity.Close()
	return d.Signer, nil
}

// createSigner creates or reuses a's device in workspace and returns its signing key.
func createSigner(a *App, workspace string) (signing.Signer, error) {
	d, _, _, err := a.Identities.Create(workspace)
	if err != nil {
		return nil, err
	}
	_ = d.Identity.Close()
	return d.Signer, nil
}

// readableBy reports whether the device of reader can decrypt revision st.
func readableBy(t *testing.T, s *session, reader *App, st *wsp.VerifiedState) bool {
	t.Helper()
	d, err := reader.Identities.Load(s.workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	ciphertext, err := wsp.ReadCiphertext(bg, s.store, st)
	if err != nil {
		t.Fatal(err)
	}
	_, err = decryptSecretsObject(ciphertext, d.Identity)
	return err == nil
}

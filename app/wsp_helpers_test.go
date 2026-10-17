package app

import (
	"context"
	"testing"

	apptest "github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
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
	signer, err := author.Identities.LoadSigner(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = signer.Close() }()
	st := wsp.State{Workspace: workspace, Resource: resource, Parents: parents, Control: control,
		Ciphertext: digest.FromBytes(ciphertext), Author: signer.Public().DeviceID(), CreatedAt: createdAt}
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

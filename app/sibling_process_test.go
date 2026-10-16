package app

import (
	"context"
	"io"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// hookedRefs runs another process "in the gap" between storage calls of the
// process under test, or answers one Get with a stale digest.
type hookedRefs struct {
	storage.Refs
	staleOnce *digest.Digest // answer the next Get of the secrets ref with this
	afterPut  func(key string)
}

func (h *hookedRefs) Get(ctx context.Context, key string) (digest.Digest, storage.Version, error) {
	d, v, err := h.Refs.Get(ctx, key)
	if key == secretsTag("default") && h.staleOnce != nil {
		d, h.staleOnce = *h.staleOnce, nil
	}
	return d, v, err
}

func (h *hookedRefs) Put(ctx context.Context, key string, d digest.Digest, v storage.Version) error {
	err := h.Refs.Put(ctx, key, d, v)
	if err == nil && h.afterPut != nil {
		h.afterPut(key)
	}
	return err
}

type hookedBlobs struct {
	storage.Blobs
	beforePut func()
}

func (h *hookedBlobs) Put(ctx context.Context, r io.Reader) (digest.Digest, error) {
	if h.beforePut != nil {
		h.beforePut()
	}
	return h.Blobs.Put(ctx, r)
}

// twinOf is the same device as a: same signing key, same encryption identity,
// same checkpoint file. It models a second enbu process (a GUI, a script) that
// runs while the first one is in the middle of an operation.
func twinOf(t *testing.T, a *App) *App {
	t.Helper()
	twin := newDevice(t, a)
	twin.Identities, twin.CheckpointDir = a.Identities, a.CheckpointDir
	return twin
}

func mustSecrets(t *testing.T, a *App, env string) map[string]string {
	t.Helper()
	got, err := a.ListSecrets(bg, env)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The twin publishes and accepts a newer state after this process fetched the
// ref but before it compared the state with the checkpoint. That is not a
// rollback: storage has the newer state, this process just read a moment too
// early.
func TestSiblingAdvancingTheCheckpointDuringAReadIsNotARollback(t *testing.T) {
	alice := newAlice(t)
	twin := twinOf(t, alice)
	base := alice.Storage.Refs
	old, _, err := base.Get(bg, secretsTag("default"))
	if err != nil {
		t.Fatal(err)
	}
	if err := twin.AddSecret(bg, "default", "TWIN", "t"); err != nil {
		t.Fatal(err)
	}
	// Alice's next fetch returns what she would have fetched a moment ago.
	alice.Storage.Refs = &hookedRefs{Refs: base, staleOnce: &old}
	got, err := alice.ListSecrets(bg, "default")
	if err != nil {
		t.Fatalf("read after a sibling advanced the checkpoint: %v", err)
	}
	if got["TWIN"] != "t" {
		t.Fatalf("read returned the stale state: %v", got)
	}
}

// Storage really serving the old state is still a rollback, even when the
// checkpoint moved by another process of this device.
func TestStorageStuckOnTheOldStateIsStillARollback(t *testing.T) {
	alice := newAlice(t)
	twin := twinOf(t, alice)
	old, _, err := alice.Storage.Refs.Get(bg, secretsTag("default"))
	if err != nil {
		t.Fatal(err)
	}
	if err := twin.AddSecret(bg, "default", "TWIN", "t"); err != nil {
		t.Fatal(err)
	}
	_, version, _ := alice.Storage.Refs.Get(bg, secretsTag("default"))
	if err := alice.Storage.Refs.Put(bg, secretsTag("default"), old, version); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ListSecrets(bg, "default"); !isRollback(err) {
		t.Fatalf("old state accepted: %v", err)
	}
}

// The twin publishes between this process reading the state and publishing
// its own. The checkpoint then names the twin's state at the sequence this
// process is about to use. That is an ordinary lost race, so the write must
// retry on the twin's state instead of reporting a rollback.
func TestSiblingPublishingBeforeOurPublishIsAConflictNotARollback(t *testing.T) {
	alice := newAlice(t)
	twin := twinOf(t, alice)
	var fired bool
	// The first Blobs.Put of a write is the ciphertext, after the read phase.
	alice.Storage.Blobs = &hookedBlobs{Blobs: alice.Storage.Blobs, beforePut: func() {
		if fired {
			return
		}
		fired = true
		if err := twin.AddSecret(bg, "default", "TWIN", "t"); err != nil {
			t.Errorf("twin: %v", err)
		}
	}}
	if err := alice.AddSecret(bg, "default", "ALICE", "a"); err != nil {
		t.Fatalf("add while a sibling published first: %v", err)
	}
	got := mustSecrets(t, alice, "default")
	if got["ALICE"] != "a" || got["TWIN"] != "t" {
		t.Fatalf("both writes should be kept: %v", got)
	}
}

// The twin reads this process's freshly published state and publishes on top
// of it before this process records its own in the checkpoint. The publish
// succeeded and the twin built on it, so the operation succeeded.
func TestSiblingBuildingOnOurPublishBeforeOurAcceptIsASuccess(t *testing.T) {
	alice := newAlice(t)
	twin := twinOf(t, alice)
	var fired bool
	alice.Storage.Refs = &hookedRefs{Refs: alice.Storage.Refs, afterPut: func(key string) {
		if key != secretsTag("default") || fired {
			return
		}
		fired = true
		if err := twin.AddSecret(bg, "default", "TWIN", "t"); err != nil {
			t.Errorf("twin: %v", err)
		}
	}}
	if err := alice.AddSecret(bg, "default", "ALICE", "a"); err != nil {
		t.Fatalf("add that a sibling built on: %v", err)
	}
	got := mustSecrets(t, alice, "default")
	if got["ALICE"] != "a" || got["TWIN"] != "t" {
		t.Fatalf("both writes should be kept: %v", got)
	}
}

func isRollback(err error) bool { return apperr.Is(err, apperr.CodeRollback) }

package wsp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	digest "github.com/opencontainers/go-digest"
)

// workspace creates a store whose genesis is founded by alice.
func workspace(t *testing.T) (*storage.Store, actor, digest.Digest) {
	t.Helper()
	store := storagetest.NewMemory()
	alice := newActor(t, true)
	v, err := CreateControl(context.Background(), store, testWorkspace, alice.p, alice.signer)
	if err != nil {
		t.Fatal(err)
	}
	return store, alice, v.Digest
}

func addMember(t *testing.T, store *storage.Store, genesis digest.Digest, by, who actor) *Verified {
	t.Helper()
	head, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := UpdateControl(context.Background(), store, head, by.signer, func(c *Control) error {
		c.Principals = append(c.Principals, who.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func TestControlGrowsOnlyThroughSignedChain(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	v := addMember(t, store, genesis, alice, bob)
	head, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if head.Digest != v.Digest || head.Generation != 1 || len(head.Recipients()) != 2 {
		t.Fatalf("unexpected head: %+v", head.Control)
	}
	if _, ok := head.Principal(bob.p.ID); !ok {
		t.Fatal("bob is not a principal")
	}
}

func TestRecipientInjectionIsIgnored(t *testing.T) {
	store, alice, genesis := workspace(t)
	attacker := newActor(t, false)
	ctx := context.Background()
	// Anything an attacker can write under other names has no effect on the set.
	for _, name := range []string{"recipient-" + attacker.p.Recipient, "request-" + string(attacker.p.ID)} {
		d, _ := store.Blobs.Put(ctx, bytesReader([]byte(attacker.p.Recipient)))
		if err := store.Refs.Put(ctx, name, d, ""); err != nil {
			t.Fatal(err)
		}
	}
	head, err := LoadControl(ctx, store, testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := head.Recipients(); len(got) != 1 || got[0] != alice.p.Recipient {
		t.Fatalf("recipient set changed: %v", got)
	}
}

func TestAttackerControlRejected(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	head, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	mallory := newActor(t, true)
	forged := Control{Workspace: testWorkspace, Generation: 1, Previous: head.Digest, Author: mallory.p.ID,
		Principals: []Principal{alice.p, mallory.p}}
	blob, err := SignControl(forged, mallory.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNext(head.Verified, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control signed by an outsider was accepted: %v", err)
	}
	// Pointing the head ref at it makes the load fail rather than trust it.
	if err := putControl(ctx, store, blob, head.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged head accepted: %v", err)
	}
}

func TestMemberCannotChangeControl(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	addMember(t, store, genesis, alice, bob)
	head, _ := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	if _, err := UpdateControl(context.Background(), store, head, bob.signer, func(*Control) error { return nil }); err == nil {
		t.Fatal("non-admin updated the control")
	}
	// Even if bob forges one by hand, verification fails.
	forged := head.Control
	forged.Generation, forged.Previous, forged.Author = 2, head.Digest, bob.p.ID
	blob, err := SignControl(forged, bob.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyNext(head.Verified, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("member-signed control accepted: %v", err)
	}
}

func TestGenesisMustMatchTrustedDigest(t *testing.T) {
	store, _, genesis := workspace(t)
	ctx := context.Background()
	other := digest.FromString("other")
	if _, err := LoadControl(ctx, store, testWorkspace, other, nil); err == nil {
		t.Fatal("untrusted genesis accepted")
	}
	if _, err := LoadControl(ctx, store, "0192f3a0-7c1e-7a55-9d3c-000000000000", genesis, nil); err == nil {
		t.Fatal("control of another workspace accepted")
	}
}

func TestRollbackAndForkRejected(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	bob := newActor(t, false)
	v1 := addMember(t, store, genesis, alice, bob)
	carol := newActor(t, false)
	head, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	v2, err := UpdateControl(ctx, store, head, alice.signer, func(c *Control) error {
		c.Principals = append(c.Principals, carol.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cp := &Checkpoint{Generation: v2.Generation, Digest: v2.Digest}

	// Storage rewinds the head to generation 1.
	_, version, _ := store.Refs.Get(ctx, ControlRef)
	if err := store.Refs.Put(ctx, ControlRef, v1.Digest, version); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, cp); !errors.Is(err, ErrRollback) {
		t.Fatalf("rolled back head accepted: %v", err)
	}
	// Without a checkpoint the same old head is indistinguishable from current.
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, nil); err != nil {
		t.Fatalf("old head without checkpoint: %v", err)
	}

	// A fork at the same generation with a different digest.
	dave := newActor(t, false)
	h1, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	fork, err := UpdateControl(ctx, store, h1, alice.signer, func(c *Control) error {
		c.Principals = append(c.Principals, dave.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if fork.Generation != v2.Generation || fork.Digest == v2.Digest {
		t.Fatal("test setup did not create a fork")
	}
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, cp); !errors.Is(err, ErrRollback) {
		t.Fatalf("fork accepted: %v", err)
	}
}

func TestCheckpointAnchorsAndAdvances(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	bob := newActor(t, false)
	v1 := addMember(t, store, genesis, alice, bob)
	cp := &Checkpoint{Generation: v1.Generation, Digest: v1.Digest}
	head, err := LoadControl(ctx, store, testWorkspace, genesis, cp)
	if err != nil || head.Digest != v1.Digest {
		t.Fatalf("head at checkpoint: %v", err)
	}
	carol := newActor(t, false)
	v2, err := UpdateControl(ctx, store, head, alice.signer, func(c *Control) error {
		c.Principals = append(c.Principals, carol.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	head, err = LoadControl(ctx, store, testWorkspace, genesis, cp)
	if err != nil || head.Digest != v2.Digest {
		t.Fatalf("advance past checkpoint: %v", err)
	}
}

func TestConcurrentUpdateConflicts(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	head, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	if _, err := UpdateControl(ctx, store, head, alice.signer, func(c *Control) error { c.Principals = append(c.Principals, newActor(t, false).p); return nil }); err != nil {
		t.Fatal(err)
	}
	// head still carries the old ref version.
	_, err := UpdateControl(ctx, store, head, alice.signer, func(c *Control) error { c.Principals = append(c.Principals, newActor(t, false).p); return nil })
	if !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := CreateControl(ctx, store, testWorkspace, alice.p, alice.signer); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("second genesis: %v", err)
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	store, alice, genesis := workspace(t)
	head, _ := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	bob := newActor(t, false)
	_, err := UpdateControl(context.Background(), store, head, alice.signer, func(c *Control) error {
		c.Principals = []Principal{bob.p}
		return nil
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("control without admin: %v", err)
	}
}

// liarBlobs serves different bytes than the digest names and skips the check a
// real backend does, as a hostile or broken storage might.
type liarBlobs struct {
	storage.Blobs
	lie digest.Digest
}

func (l liarBlobs) Open(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
	if d == l.lie {
		return io.NopCloser(strings.NewReader("not the bytes this digest names")), nil
	}
	return l.Blobs.Open(ctx, d)
}

func TestLoadControlRejectsBlobThatDoesNotMatchItsDigest(t *testing.T) {
	store, _, genesis := workspace(t)
	lying := &storage.Store{Blobs: liarBlobs{Blobs: store.Blobs, lie: genesis}, Refs: store.Refs}
	if _, err := LoadControl(context.Background(), lying, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a blob that does not match its digest was trusted: %v", err)
	}
}

func TestLoadControlRejectsAnOversizedBlob(t *testing.T) {
	store := storagetest.NewMemory()
	ctx := context.Background()
	d, err := store.Blobs.Put(ctx, bytes.NewReader(make([]byte, MaxSignedBytes+1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Refs.Put(ctx, ControlRef, d, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControl(ctx, store, testWorkspace, digest.FromString("genesis"), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an oversized control was read: %v", err)
	}
}

func TestLoadControlRejectsAChainThatIsTooLong(t *testing.T) {
	store, alice, genesis := workspace(t)
	for i := 0; i < 4; i++ {
		addMember(t, store, genesis, alice, newActor(t, false))
	}
	defer func(old int) { maxChain = old }(maxChain)
	maxChain = 3
	if _, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a chain longer than the limit was walked: %v", err)
	}
	maxChain = 10
	if _, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil); err != nil {
		t.Fatalf("a chain within the limit was rejected: %v", err)
	}
}

// wrongDigestBlobs stores correctly but reports another digest.
type wrongDigestBlobs struct{ storage.Blobs }

func (wrongDigestBlobs) Put(context.Context, io.Reader) (digest.Digest, error) {
	return digest.FromString("something else"), nil
}

func TestPublishingChecksTheDigestStorageReports(t *testing.T) {
	store := storagetest.NewMemory()
	alice := newActor(t, true)
	blob, _, err := NewGenesis(testWorkspace, alice.p, alice.signer)
	if err != nil {
		t.Fatal(err)
	}
	broken := &storage.Store{Blobs: wrongDigestBlobs{store.Blobs}, Refs: store.Refs}
	if err := PublishGenesis(context.Background(), broken, blob); err == nil {
		t.Fatal("a control was published under a digest that does not match its bytes")
	}
	if _, _, err := store.Refs.Get(context.Background(), ControlRef); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a head was set anyway: %v", err)
	}
}

func TestGenesisCanBePreparedBeforeItIsPublished(t *testing.T) {
	store := storagetest.NewMemory()
	ctx := context.Background()
	alice := newActor(t, true)
	blob, d, err := NewGenesis(testWorkspace, alice.p, alice.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Refs.Get(ctx, ControlRef); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("preparing a genesis published it: %v", err)
	}
	if err := PublishGenesis(ctx, store, blob); err != nil {
		t.Fatal(err)
	}
	head, err := LoadControl(ctx, store, testWorkspace, d, nil)
	if err != nil || head.Generation != 0 {
		t.Fatalf("load: %v", err)
	}
	if err := PublishGenesis(ctx, store, blob); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("second genesis: %v", err)
	}
}

func TestControlAtFindsOlderGenerationsFromTheVerifiedHead(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	bob, carol := newActor(t, false), newActor(t, false)
	v1 := addMember(t, store, genesis, alice, bob)
	v2 := addMember(t, store, genesis, alice, carol)
	head, err := LoadControl(ctx, store, testWorkspace, genesis, nil)
	if err != nil || head.Digest != v2.Digest {
		t.Fatalf("head: %v", err)
	}
	for gen, want := range map[uint64]*Verified{2: v2, 1: v1} {
		got, err := ControlAt(ctx, store, head.Verified, gen, want.Digest)
		if err != nil || got.Digest != want.Digest || got.Generation != gen || len(got.Principals) != len(want.Principals) {
			t.Fatalf("generation %d: %+v %v", gen, got, err)
		}
	}
	zero, err := ControlAt(ctx, store, head.Verified, 0, genesis)
	if err != nil || zero.Generation != 0 || len(zero.Principals) != 1 {
		t.Fatalf("genesis: %+v %v", zero, err)
	}
	// Bob is only in generations 1 and 2.
	if _, ok := zero.Principal(bob.p.ID); ok {
		t.Fatal("bob was in the genesis control")
	}
	if _, ok := v1.Principal(bob.p.ID); !ok {
		t.Fatal("bob should be in generation 1")
	}
}

func TestControlAtRejectsWhatTheChainDoesNotContain(t *testing.T) {
	store, alice, genesis := workspace(t)
	ctx := context.Background()
	v1 := addMember(t, store, genesis, alice, newActor(t, false))
	head, _ := LoadControl(ctx, store, testWorkspace, genesis, nil)
	if _, err := ControlAt(ctx, store, head.Verified, 5, v1.Digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a generation above the head: %v", err)
	}
	if _, err := ControlAt(ctx, store, head.Verified, 1, digest.FromString("other")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a digest that is not the head's: %v", err)
	}
	if _, err := ControlAt(ctx, store, head.Verified, 0, digest.FromString("other")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a digest that is not the genesis: %v", err)
	}
}

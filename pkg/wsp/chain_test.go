package wsp

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	digest "github.com/opencontainers/go-digest"
)

// workspace creates a store whose genesis is founded by alice.
func workspace(t *testing.T) (storage.Store, actor, digest.Digest) {
	t.Helper()
	store := storagetest.NewMemory()
	alice := newActor(t, true)
	v, err := CreateControl(context.Background(), store, testWorkspace, alice.p, alice.signer)
	if err != nil {
		t.Fatal(err)
	}
	return store, alice, v.Digest
}

func load(t *testing.T, store storage.Store, genesis digest.Digest) *ControlView {
	t.Helper()
	view, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	return view
}

func addMember(t *testing.T, store storage.Store, genesis digest.Digest, by, who actor) *Verified {
	t.Helper()
	v, err := UpdateControl(context.Background(), store, load(t, store, genesis), by.signer, func(c *Control) error {
		c.Principals = append(c.Principals, who.p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestControlGrowsOnlyThroughSignedChain(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	v := addMember(t, store, genesis, alice, bob)
	head, err := load(t, store, genesis).Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.Digest != v.Digest || head.Height != 1 || len(head.Recipients()) != 2 {
		t.Fatalf("unexpected head: %+v", head.Control)
	}
	if _, ok := head.Principal(bob.p.ID); !ok {
		t.Fatal("bob is not a principal")
	}
}

func publishRaw(t *testing.T, store storage.Store, blob []byte) {
	t.Helper()
	if err := publishControl(context.Background(), store, blob); err != nil {
		t.Fatal(err)
	}
}

// Anyone who can write to storage can publish a Control. Only one chained to the
// genesis through admin signatures counts.
func TestControlsWithoutAuthorityAreIgnored(t *testing.T) {
	store, alice, genesis := workspace(t)
	mallory, bob := newActor(t, true), newActor(t, false)
	g := load(t, store, genesis).Heads[0]

	forged, err := SignControl(Control{Workspace: testWorkspace, Parents: []digest.Digest{g.Digest}, Height: 1, Principals: []Principal{alice.p, mallory.p}, Author: mallory.p.ID}, mallory.signer)
	if err != nil {
		t.Fatal(err)
	}
	publishRaw(t, store, forged)
	member, _ := SignControl(Control{Workspace: testWorkspace, Parents: []digest.Digest{g.Digest}, Height: 1, Principals: []Principal{alice.p, bob.p}, Author: alice.p.ID}, alice.signer)
	_ = member
	orphan, _ := SignControl(Control{Workspace: testWorkspace, Parents: []digest.Digest{digest.FromString("nowhere")}, Height: 1, Principals: []Principal{alice.p}, Author: alice.p.ID}, alice.signer)
	publishRaw(t, store, orphan)

	view := load(t, store, genesis)
	head, err := view.Head()
	if err != nil || head.Digest != genesis {
		t.Fatalf("unauthorized controls changed the head: %v %v", head, err)
	}
	if len(view.Digests()) != 1 {
		t.Fatalf("verified = %v", view.Digests())
	}
}

func TestMemberCannotChangeControl(t *testing.T) {
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	addMember(t, store, genesis, alice, bob)
	_, err := UpdateControl(context.Background(), store, load(t, store, genesis), bob.signer, func(c *Control) error { return nil })
	if err == nil {
		t.Fatal("a member published a control")
	}
}

func TestGenesisMustMatchTrustedDigest(t *testing.T) {
	store, _, _ := workspace(t)
	other := newActor(t, true)
	blob, d := genesisOf(t, other)
	publishRaw(t, store, blob)
	if _, err := LoadControl(context.Background(), store, testWorkspace, d, nil); err != nil {
		t.Fatalf("another workspace founder's genesis loads on its own: %v", err)
	}
	if _, err := LoadControl(context.Background(), store, testWorkspace, digest.FromString("wrong"), nil); err == nil {
		t.Fatal("untrusted genesis accepted")
	}
	if _, err := LoadControl(context.Background(), store, "0192f3a0-7c1e-7a55-9d3c-000000000000", d, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("genesis of another workspace: %v", err)
	}
}

// Without compare-and-swap two admins can publish from the same head. The second
// one finds out because it loads the DAG again.
func TestConcurrentUpdateForksAndIsResolvedByAnAdmin(t *testing.T) {
	ctx := context.Background()
	store, alice, genesis := workspace(t)
	bob, carol, dave := newActor(t, true), newActor(t, false), newActor(t, false)
	addMember(t, store, genesis, alice, bob)

	stale := load(t, store, genesis)
	if _, err := UpdateControl(ctx, store, stale, alice.signer, func(c *Control) error {
		c.Principals = append(c.Principals, carol.p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err := UpdateControl(ctx, store, stale, bob.signer, func(c *Control) error {
		c.Principals = append(c.Principals, dave.p)
		return nil
	})
	var fork *ForkError
	if !errors.Is(err, ErrControlFork) || !errors.As(err, &fork) || len(fork.Heads) != 2 {
		t.Fatalf("concurrent update: %v", err)
	}

	view := load(t, store, genesis)
	if !view.Forked() {
		t.Fatal("storage shows no fork")
	}
	if _, err := view.Head(); !errors.Is(err, ErrControlFork) {
		t.Fatalf("head of a forked DAG: %v", err)
	}
	if _, err := UpdateControl(ctx, store, view, alice.signer, func(*Control) error { return nil }); !errors.Is(err, ErrControlFork) {
		t.Fatalf("update on a forked DAG: %v", err)
	}
	if _, err := ResolveFork(ctx, store, view, carol.signer, func(*Control) error { return nil }); err == nil {
		t.Fatal("a member resolved the fork")
	}
	resolved, err := ResolveFork(ctx, store, view, alice.signer, func(c *Control) error {
		kept := c.Principals[:0:0]
		for _, p := range c.Principals {
			if p.ID != dave.p.ID {
				kept = append(kept, p)
			}
		}
		c.Principals = kept
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	head, err := load(t, store, genesis).Head()
	if err != nil || head.Digest != resolved.Digest {
		t.Fatalf("head after resolution: %v %v", head, err)
	}
	if _, ok := head.Principal(dave.p.ID); ok {
		t.Fatal("dave survived the resolution")
	}
	if _, ok := head.Principal(carol.p.ID); !ok {
		t.Fatal("carol was dropped")
	}
	if _, err := ResolveFork(ctx, store, head2view(t, store, genesis), alice.signer, func(*Control) error { return nil }); err == nil {
		t.Fatal("resolved a DAG that is not forked")
	}
}

func head2view(t *testing.T, store storage.Store, genesis digest.Digest) *ControlView {
	return load(t, store, genesis)
}

func TestStaleListingStillFindsParentsByDigest(t *testing.T) {
	ctx := context.Background()
	store, alice, genesis := workspace(t)
	bob, carol := newActor(t, false), newActor(t, false)
	addMember(t, store, genesis, alice, bob)
	v2 := addMember(t, store, genesis, alice, carol)
	// The listing shows only the newest Control; its ancestors are fetched by digest.
	stale := storagetest.Wrap(store, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			return []digest.Digest{v2.Digest}, nil
		},
	})
	view, err := LoadControl(ctx, stale, testWorkspace, genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	if head, err := view.Head(); err != nil || head.Digest != v2.Digest {
		t.Fatalf("head = %v %v", head, err)
	}
}

func TestLoadControlDetectsAHiddenAcceptedControl(t *testing.T) {
	ctx := context.Background()
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	v1 := addMember(t, store, genesis, alice, bob)
	cp := []digest.Digest{v1.Digest}
	hidden := storagetest.Wrap(store, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			return nil, nil
		},
		Fetch: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
			if rev == v1.Digest {
				return storage.Object{}, storage.ErrNotFound
			}
			return next.Fetch(ctx, kind, scope, rev)
		},
	})
	if _, err := LoadControl(ctx, hidden, testWorkspace, genesis, cp); !errors.Is(err, ErrRollback) {
		t.Fatalf("hidden control: %v", err)
	}
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, cp); err != nil {
		t.Fatalf("honest storage: %v", err)
	}
}

func TestLoadControlSkipsDamagedAndRefusesAnOversizedDAG(t *testing.T) {
	ctx := context.Background()
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	v1 := addMember(t, store, genesis, alice, bob)
	damaged := storagetest.Wrap(store, storagetest.Hooks{
		Fetch: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
			if rev == v1.Digest {
				return storage.Object{}, storage.ErrCorrupt
			}
			return next.Fetch(ctx, kind, scope, rev)
		},
	})
	view, err := LoadControl(ctx, damaged, testWorkspace, genesis, nil)
	if err != nil || view.Heads[0].Digest != genesis {
		t.Fatalf("damaged control: %v %v", view, err)
	}

	carol := newActor(t, false)
	addMember(t, store, genesis, alice, carol)
	old := maxControls
	maxControls = 1
	t.Cleanup(func() { maxControls = old })
	if _, err := LoadControl(ctx, store, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized DAG: %v", err)
	}
}

func TestLastAdminCannotBeRemoved(t *testing.T) {
	store, alice, genesis := workspace(t)
	_, err := UpdateControl(context.Background(), store, load(t, store, genesis), alice.signer, func(c *Control) error {
		c.Principals = nil
		return nil
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("removing every principal: %v", err)
	}
	bob := newActor(t, false)
	addMember(t, store, genesis, alice, bob)
	_, err = UpdateControl(context.Background(), store, load(t, store, genesis), alice.signer, func(c *Control) error {
		c.Principals = []Principal{bob.p}
		return nil
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("leaving no admin: %v", err)
	}
}

func TestGenesisCanBePreparedBeforeItIsPublished(t *testing.T) {
	ctx := context.Background()
	store := storagetest.NewMemory()
	alice := newActor(t, true)
	blob, d, err := NewGenesis(testWorkspace, alice.p, alice.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControl(ctx, store, testWorkspace, d, nil); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("nothing published yet: %v", err)
	}
	if err := PublishGenesis(ctx, store, blob); err != nil {
		t.Fatal(err)
	}
	if err := PublishGenesis(ctx, store, blob); err != nil {
		t.Fatalf("publishing the genesis again must be idempotent: %v", err)
	}
	if view, err := LoadControl(ctx, store, testWorkspace, d, nil); err != nil || view.Heads[0].Digest != d {
		t.Fatalf("genesis does not load: %v", err)
	}
}

var _ = signing.DeviceID("")

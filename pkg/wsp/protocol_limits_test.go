package wsp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

func TestControlBudgetCountsMalformedAndMissingObjects(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("missing-%t", missing), func(t *testing.T) {
			base, _, genesis := workspace(t)
			refs := []digest.Digest{digest.FromString("bad-a"), digest.FromString("bad-b")}
			previous := maxControls
			maxControls = 2
			t.Cleanup(func() { maxControls = previous })
			reads := 0
			store := storagetest.Wrap(base, storagetest.Hooks{
				Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) { return refs, nil },
				FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
					reads++
					if rev == genesis {
						return next.FetchHead(ctx, kind, scope, rev)
					}
					if missing {
						return nil, storage.ErrNotFound
					}
					return []byte("invalid"), nil
				},
			})
			if _, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
				t.Fatalf("untrusted controls bypassed count budget: %v", err)
			}
			if reads > 2 {
				t.Fatalf("fetched %d heads beyond budget 2", reads)
			}
		})
	}
}

func TestControlReadsARejectedReferenceOnce(t *testing.T) {
	base, _, genesis := workspace(t)
	bad := digest.FromString("repeated invalid control")
	reads := 0
	store := storagetest.Wrap(base, storagetest.Hooks{
		Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) {
			return []digest.Digest{bad, bad, bad}, nil
		},
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			if rev == genesis {
				return next.FetchHead(ctx, kind, scope, rev)
			}
			reads++
			return []byte("invalid"), nil
		},
	})
	if _, err := LoadControl(context.Background(), store, testWorkspace, genesis, nil); err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Fatalf("fetched repeated rejected reference %d times", reads)
	}
}

func TestControlChecksByteBudgetAfterTheLastHead(t *testing.T) {
	for _, over := range []bool{false, true} {
		t.Run(fmt.Sprintf("over-%t", over), func(t *testing.T) {
			base, _, genesis := workspace(t)
			root, err := base.FetchHead(context.Background(), storage.KindControl, "", genesis)
			if err != nil {
				t.Fatal(err)
			}
			junk := []byte("invalid control metadata")
			previous := maxControlBytes
			maxControlBytes = len(root) + len(junk)
			if over {
				maxControlBytes--
			}
			t.Cleanup(func() { maxControlBytes = previous })
			bad := digest.FromBytes(junk)
			store := storagetest.Wrap(base, storagetest.Hooks{
				Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) {
					return []digest.Digest{bad}, nil
				},
				FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
					if rev == genesis {
						return next.FetchHead(ctx, kind, scope, rev)
					}
					return junk, nil
				},
			})
			_, err = LoadControl(context.Background(), store, testWorkspace, genesis, nil)
			if over != errors.Is(err, ErrInvalid) {
				t.Fatalf("last-head byte budget over=%t: %v", over, err)
			}
		})
	}
}

func TestControlCountsGenesisAgainstItsByteBudget(t *testing.T) {
	base, _, genesis := workspace(t)
	blob, err := base.FetchHead(context.Background(), storage.KindControl, "", genesis)
	if err != nil {
		t.Fatal(err)
	}
	previous := maxControlBytes
	maxControlBytes = len(blob) - 1
	t.Cleanup(func() { maxControlBytes = previous })
	if _, err := LoadControl(context.Background(), base, testWorkspace, genesis, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("genesis bypassed byte budget: %v", err)
	}
}

func TestStateLoadingBoundsAggregateInvalidHeadBytes(t *testing.T) {
	f := newStateFixture(t)
	refs := make([]digest.Digest, 40)
	for i := range refs {
		refs[i] = digest.FromString(fmt.Sprintf("oversized-state-%d", i))
	}
	blob := bytes.Repeat([]byte("!"), 1<<20)
	reads := 0
	store := storagetest.Wrap(f.store, storagetest.Hooks{
		Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) { return refs, nil },
		FetchHead: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) ([]byte, error) {
			reads++
			return blob, nil
		},
	})
	ctx := WithSerialHeadReads(context.Background())
	if _, err := LoadStates(ctx, store, f.view, testWorkspace, testResource); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state metadata bypassed aggregate read budget: %v", err)
	}
	if reads > 32+headFetches {
		t.Fatalf("state loader read %d MiB after crossing budget", reads)
	}
}

func TestControlDiscoveryOrderDoesNotChangeAncestorReads(t *testing.T) {
	ctx := context.Background()
	base, alice, genesis := workspace(t)
	var leaves []digest.Digest
	for range 4 {
		bob := newActor(t, false)
		parent, err := SignControl(Control{Workspace: testWorkspace, Parents: []digest.Digest{genesis}, Height: 1, Principals: []Principal{alice.p, bob.p}, Author: alice.p.ID}, alice.signer)
		if err != nil {
			t.Fatal(err)
		}
		publishRaw(t, base, parent)
		child, err := SignControl(Control{Workspace: testWorkspace, Parents: []digest.Digest{digest.FromBytes(parent)}, Height: 2, Principals: []Principal{alice.p, bob.p}, Author: alice.p.ID}, alice.signer)
		if err != nil {
			t.Fatal(err)
		}
		publishRaw(t, base, child)
		leaves = append(leaves, digest.FromBytes(child))
	}
	var expected []digest.Digest
	for _, reverse := range []bool{false, true} {
		refs := append([]digest.Digest(nil), leaves...)
		if reverse {
			for i, j := 0, len(refs)-1; i < j; i, j = i+1, j-1 {
				refs[i], refs[j] = refs[j], refs[i]
			}
		}
		var reads []digest.Digest
		store := storagetest.Wrap(base, storagetest.Hooks{
			Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) { return refs, nil },
			FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
				reads = append(reads, rev)
				return next.FetchHead(ctx, kind, scope, rev)
			},
		})
		view, err := LoadControl(ctx, store, testWorkspace, genesis, nil)
		if err != nil || len(view.Heads) != 4 {
			t.Fatalf("hidden parents = %v, %v", view, err)
		}
		if len(reads) != 9 {
			t.Fatalf("ancestor traversal fetched %d heads, want nine unique heads", len(reads))
		}
		if !reverse {
			expected = reads
		} else if !reflect.DeepEqual(expected, reads) {
			t.Fatal("storage listing order changed ancestor fetch order")
		}
	}
}

func TestStateReadBudgetPermitsExactTotal(t *testing.T) {
	f := newStateFixture(t)
	rev := f.publish(t, f.state(f.alice), f.alice, "one legitimate state")
	head, err := f.store.FetchHead(context.Background(), storage.KindState, storage.StateScope(testWorkspace, testResource), rev)
	if err != nil {
		t.Fatal(err)
	}
	previous := maxStateBytes
	maxStateBytes = len(head)
	t.Cleanup(func() { maxStateBytes = previous })
	if view, err := LoadStates(context.Background(), f.store, f.view, testWorkspace, testResource); err != nil || view.Graph.Len() != 1 {
		t.Fatalf("exact state byte budget = %v, %v", view, err)
	}
	maxStateBytes--
	if _, err := LoadStates(context.Background(), f.store, f.view, testWorkspace, testResource); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over state byte budget = %v", err)
	}
}

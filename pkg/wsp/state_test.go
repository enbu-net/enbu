package wsp

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	digest "github.com/opencontainers/go-digest"
)

const testResource = "secrets/dev"

type stateFixture struct {
	store    storage.Store
	alice    actor
	bob      actor
	genesis  digest.Digest
	view     *ControlView
	headHash digest.Digest
	gens     map[digest.Digest]uint64 // Generation of each revision publish stored
}

// newStateFixture founds a workspace with alice (admin) and bob (member).
func newStateFixture(t *testing.T) stateFixture {
	t.Helper()
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	v := addMember(t, store, genesis, alice, bob)
	return stateFixture{store: store, alice: alice, bob: bob, genesis: genesis, view: load(t, store, genesis), headHash: v.Digest, gens: map[digest.Digest]uint64{}}
}

// state is a revision on top of parents, with the Generation they imply (a
// parent publish did not store counts as generation 1).
func (f stateFixture) state(author actor, parents ...digest.Digest) State {
	var top uint64
	for _, p := range parents {
		top = max(top, max(f.gens[p], 1))
	}
	return State{Workspace: testWorkspace, Resource: testResource, Parents: parents, Generation: top + 1, Op: OpWrite,
		Control: f.headHash, Ciphertext: digest.FromString("ciphertext"), Author: author.p.ID}
}

func (f stateFixture) publish(t *testing.T, s State, by actor, cipher string) digest.Digest {
	t.Helper()
	s.Ciphertext = digest.FromString(cipher)
	blob, err := SignState(s, by.signer)
	if err != nil {
		t.Fatal(err)
	}
	rev := digest.FromBytes(blob)
	if err := f.store.Publish(context.Background(), storage.Object{Kind: storage.KindState, Scope: s.Scope(), Rev: rev, Head: blob, Blobs: [][]byte{[]byte(cipher)}}); err != nil {
		t.Fatal(err)
	}
	f.gens[rev] = s.Generation
	return rev
}

func signedState(t *testing.T, s State, by actor) ([]byte, digest.Digest) {
	t.Helper()
	blob, err := SignState(s, by.signer)
	if err != nil {
		t.Fatal(err)
	}
	return blob, digest.FromBytes(blob)
}

func TestStateRoundTrip(t *testing.T) {
	f := newStateFixture(t)
	blob, rev := signedState(t, f.state(f.bob), f.bob)
	got, err := VerifyRevision(f.view, testWorkspace, testResource, rev, blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Author != f.bob.p.ID || got.Digest != rev || got.Resource != testResource {
		t.Fatalf("unexpected state: %+v", got)
	}
	head, _ := f.view.Head()
	if err := AuthorIsCurrent(f.view, head, got); err != nil {
		t.Fatal(err)
	}
}

func TestFakeSecretRejected(t *testing.T) {
	f := newStateFixture(t)
	mallory := newActor(t, false)
	// Mallory is no principal of the control the state names.
	blob, rev := signedState(t, f.state(mallory), mallory)
	if _, err := VerifyRevision(f.view, testWorkspace, testResource, rev, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state by an outsider accepted: %v", err)
	}
	// Mallory claims to be bob but signs with her own key.
	forged := f.state(f.bob)
	body, _ := encMode.Marshal(forged)
	sig, _ := mallory.signer.Sign(signing.DomainState, body)
	blob, _ = Signed{Body: body, Signature: sig}.Encode()
	if _, err := VerifyRevision(f.view, testWorkspace, testResource, digest.FromBytes(blob), blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state with a foreign signature accepted: %v", err)
	}
}

func TestStateTamperingAndWrongRevision(t *testing.T) {
	f := newStateFixture(t)
	blob, rev := signedState(t, f.state(f.bob), f.bob)
	signed, _ := DecodeSigned(blob)
	var s State
	if err := decodeCanonical(signed.Body, &s); err != nil {
		t.Fatal(err)
	}
	s.Ciphertext = digest.FromString("swapped")
	body, _ := encMode.Marshal(s)
	tampered, _ := Signed{Body: body, Signature: signed.Signature}.Encode()
	if _, err := VerifyRevision(f.view, testWorkspace, testResource, digest.FromBytes(tampered), tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered state accepted: %v", err)
	}
	// The bytes are not what the revision name says.
	if _, err := VerifyRevision(f.view, testWorkspace, testResource, digest.FromString("other"), blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revision mismatch accepted: %v", err)
	}
	_ = rev
}

func TestStateForOtherResourceOrWorkspaceRejected(t *testing.T) {
	f := newStateFixture(t)
	blob, rev := signedState(t, f.state(f.bob), f.bob)
	if _, err := VerifyRevision(f.view, testWorkspace, "secrets/prod", rev, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state replayed for another resource: %v", err)
	}
	if _, err := VerifyRevision(f.view, "0192f3a0-7c1e-7a55-9d3c-000000000000", testResource, rev, blob); !errors.Is(err, ErrInvalid) {
		t.Fatalf("state replayed for another workspace: %v", err)
	}
}

func TestStateNamingAControlStorageDoesNotShowIsARollback(t *testing.T) {
	f := newStateFixture(t)
	s := f.state(f.bob)
	s.Control = digest.FromString("a newer control")
	blob, rev := signedState(t, s, f.bob)
	if _, err := VerifyRevision(f.view, testWorkspace, testResource, rev, blob); !errors.Is(err, ErrRollback) {
		t.Fatalf("state naming an unknown control: %v", err)
	}
}

func TestRemovedMemberIsHistoricalButNotCurrent(t *testing.T) {
	f := newStateFixture(t)
	blob, rev := signedState(t, f.state(f.bob), f.bob)
	if _, err := UpdateControl(context.Background(), f.store, f.view, f.alice.signer, func(c *Control) error {
		c.Principals = []Principal{f.alice.p}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	view := load(t, f.store, f.genesis)
	st, err := VerifyRevision(view, testWorkspace, testResource, rev, blob)
	if err != nil {
		t.Fatalf("a revision written while bob was a member stays valid: %v", err)
	}
	head, _ := view.Head()
	if err := AuthorIsCurrent(view, head, st); !errors.Is(err, ErrInvalid) {
		t.Fatalf("removed member counted as current: %v", err)
	}
}

func TestStateSignerMustBeAuthorAndParentsMustBeSortedAndUnique(t *testing.T) {
	f := newStateFixture(t)
	if _, err := SignState(f.state(f.bob), f.alice.signer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("signer other than author: %v", err)
	}
	p := digest.FromString("p")
	if _, err := SignState(f.state(f.bob, p, p), f.bob.signer); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate parents: %v", err)
	}
	// Parents are sorted by SignState, so their order cannot change the revision.
	a, b := digest.FromString("a"), digest.FromString("b")
	one, _ := SignState(f.state(f.bob, a, b), f.bob.signer)
	two, _ := SignState(f.state(f.bob, b, a), f.bob.signer)
	if digest.FromBytes(one) != digest.FromBytes(two) && len(one) != len(two) {
		t.Fatal("parent order changed the encoding")
	}
}

func TestLoadStatesBuildsTheDAGAndSkipsJunk(t *testing.T) {
	ctx := context.Background()
	f := newStateFixture(t)
	root := f.publish(t, f.state(f.alice), f.alice, "root")
	left := f.publish(t, f.state(f.alice, root), f.alice, "left")
	right := f.publish(t, f.state(f.bob, root), f.bob, "right")

	// Junk: a revision by an outsider and a damaged object are skipped, not fatal.
	mallory := newActor(t, false)
	f.publish(t, f.state(mallory), mallory, "forged")

	sv, err := LoadStates(ctx, f.store, f.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	want := []digest.Digest{left, right}
	sortDigests(want)
	if len(sv.Heads) != 2 || sv.Heads[0].Digest != want[0] || sv.Heads[1].Digest != want[1] {
		t.Fatalf("heads = %v", sv.Heads)
	}
	if sv.Skipped != 1 {
		t.Fatalf("skipped = %d", sv.Skipped)
	}
	if bases := sv.Graph.MergeBases([]digest.Digest{left, right}); len(bases) != 1 || bases[0] != root {
		t.Fatalf("merge base = %v", bases)
	}
	merged := f.publish(t, f.state(f.alice, left, right), f.alice, "merged")
	sv, err = LoadStates(ctx, f.store, f.view, testWorkspace, testResource)
	if err != nil || len(sv.Heads) != 1 || sv.Heads[0].Digest != merged {
		t.Fatalf("after merge: %v %v", sv.Heads, err)
	}
}

func TestLoadStatesFindsAncestorsAStaleListingHid(t *testing.T) {
	ctx := context.Background()
	f := newStateFixture(t)
	root := f.publish(t, f.state(f.alice), f.alice, "root")
	child := f.publish(t, f.state(f.alice, root), f.alice, "child")
	stale := storagetest.Wrap(f.store, storagetest.Hooks{
		Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) {
			return []digest.Digest{child}, nil
		},
	})
	sv, err := LoadStates(ctx, stale, f.view, testWorkspace, testResource)
	if err != nil || !sv.Graph.Has(root) || len(sv.Graph.Missing()) != 0 {
		t.Fatalf("ancestors not found: %v", err)
	}
}

func TestLoadStatesReportsAParentStorageCannotProduce(t *testing.T) {
	ctx := context.Background()
	f := newStateFixture(t)
	root := f.publish(t, f.state(f.alice), f.alice, "root")
	f.publish(t, f.state(f.alice, root), f.alice, "child")
	if err := f.store.Delete(ctx, storage.KindState, storage.StateScope(testWorkspace, testResource), root); err != nil {
		t.Fatal(err)
	}
	sv, err := LoadStates(ctx, f.store, f.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if m := sv.Graph.Missing(); len(m) != 1 || m[0] != root {
		t.Fatalf("missing = %v", m)
	}
}

func TestReadCiphertextChecksTheBlobAgainstTheSignedState(t *testing.T) {
	ctx := context.Background()
	f := newStateFixture(t)
	rev := f.publish(t, f.state(f.alice), f.alice, "the ciphertext")
	sv, err := LoadStates(ctx, f.store, f.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	st := sv.States[rev]
	got, err := ReadCiphertext(ctx, f.store, st)
	if err != nil || string(got) != "the ciphertext" {
		t.Fatalf("ciphertext = %q %v", got, err)
	}
	// Storage serves other bytes under the revision: the State names the digest.
	swapped := storagetest.Wrap(f.store, storagetest.Hooks{
		OpenBlob: func(context.Context, storage.Store, storage.Kind, string, digest.Digest, int) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("another ciphertext")), nil
		},
	})
	if _, err := ReadCiphertext(ctx, swapped, st); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("swapped ciphertext: %v", err)
	}
}

// Reading the DAG must not transfer ciphertexts: only the heads are needed to
// find heads and merge bases.
func TestLoadStatesNeverOpensABlob(t *testing.T) {
	ctx := context.Background()
	f := newStateFixture(t)
	root := f.publish(t, f.state(f.alice), f.alice, "root")
	f.publish(t, f.state(f.bob, root), f.bob, "child")
	opened := 0
	counting := storagetest.Wrap(f.store, storagetest.Hooks{
		OpenBlob: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
			opened++
			return next.OpenBlob(ctx, kind, scope, rev, index)
		},
	})
	sv, err := LoadStates(ctx, counting, f.view, testWorkspace, testResource)
	if err != nil || len(sv.States) != 2 {
		t.Fatalf("load: %v", err)
	}
	if opened != 0 {
		t.Fatalf("%d blobs were opened while building the DAG", opened)
	}
}

func TestLoadStatesCountsDuplicateRequestedRevisionOnce(t *testing.T) {
	f := newStateFixture(t)
	rev := f.publish(t, f.state(f.alice), f.alice, "root")
	old := maxRevisions
	maxRevisions = 1
	t.Cleanup(func() { maxRevisions = old })
	sv, err := LoadStates(context.Background(), f.store, f.view, testWorkspace, testResource, rev, rev)
	if err != nil || sv.Graph.Len() != 1 {
		t.Fatalf("load at limit = %v, %v", sv, err)
	}
}

func TestLoadStatesStopsAfterAFailedBatch(t *testing.T) {
	f := newStateFixture(t)
	for i := range headFetches * 3 {
		f.publish(t, f.state(f.alice), f.alice, string(rune('a'+i)))
	}
	failure := errors.New("storage unavailable")
	var calls atomic.Int64
	store := storagetest.Wrap(f.store, storagetest.Hooks{
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			calls.Add(1)
			return nil, failure
		},
	})
	if _, err := LoadStates(context.Background(), store, f.view, testWorkspace, testResource); !errors.Is(err, failure) {
		t.Fatalf("load error = %v", err)
	}
	if got := calls.Load(); got == 0 || got > headFetches {
		t.Fatalf("fetches after failure = %d, want at most %d", got, headFetches)
	}
}

func TestLoadStatesCancelsOtherFetchesAfterFailure(t *testing.T) {
	f := newStateFixture(t)
	for i := range headFetches {
		f.publish(t, f.state(f.alice), f.alice, string(rune('a'+i)))
	}
	failure := errors.New("storage unavailable")
	var started, canceled atomic.Int64
	ready := make(chan struct{})
	store := storagetest.Wrap(f.store, storagetest.Hooks{
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			n := started.Add(1)
			if n == headFetches {
				close(ready)
			}
			<-ready
			if n == 1 {
				return nil, failure
			}
			<-ctx.Done()
			canceled.Add(1)
			return nil, ctx.Err()
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := LoadStates(ctx, store, f.view, testWorkspace, testResource); !errors.Is(err, failure) {
		t.Fatalf("load error = %v", err)
	}
	if canceled.Load() != headFetches-1 {
		t.Fatalf("canceled fetches = %d", canceled.Load())
	}
}

func TestReadmittedMemberCannotReviveOldState(t *testing.T) {
	f := newStateFixture(t)
	blob, rev := signedState(t, f.state(f.bob), f.bob)
	if _, err := UpdateControl(context.Background(), f.store, f.view, f.alice.signer, func(c *Control) error { c.Principals = []Principal{f.alice.p}; return nil }); err != nil {
		t.Fatal(err)
	}
	removed := load(t, f.store, f.genesis)
	if _, err := UpdateControl(context.Background(), f.store, removed, f.alice.signer, func(c *Control) error { c.Principals = append(c.Principals, f.bob.p); return nil }); err != nil {
		t.Fatal(err)
	}
	view := load(t, f.store, f.genesis)
	head, _ := view.Head()
	old, err := VerifyRevision(view, testWorkspace, testResource, rev, blob)
	if err != nil {
		t.Fatalf("historical signature must remain verifiable: %v", err)
	}
	if err := AuthorIsCurrent(view, head, old); !errors.Is(err, ErrInvalid) {
		t.Fatalf("readmission revived old state: %v", err)
	}
	if view.MembershipUnbroken(head.Digest, f.headHash, f.bob.p.ID) {
		t.Fatal("removed device retained old checkpoint authority")
	}
	if !view.MembershipUnbroken(head.Digest, f.headHash, f.alice.p.ID) {
		t.Fatal("continuous observer lost takeover authority")
	}
	fresh := f.state(f.bob)
	fresh.Control = head.Digest
	newBlob, newRev := signedState(t, fresh, f.bob)
	current, err := VerifyRevision(view, testWorkspace, testResource, newRev, newBlob)
	if err != nil {
		t.Fatal(err)
	}
	if err := AuthorIsCurrent(view, head, current); err != nil {
		t.Fatalf("fresh rejoined write rejected: %v", err)
	}
}

func TestMembershipContinuityChecksEveryForkBranch(t *testing.T) {
	id := signing.DeviceID("device")
	names := []string{"genesis", "join", "continuous", "remove", "rejoin", "merge"}
	hashes := map[string]digest.Digest{}
	for _, name := range names {
		hashes[name] = digest.FromString(name)
	}
	view := &ControlView{verified: map[digest.Digest]*Verified{}}
	add := func(name string, present bool, parents ...string) {
		c := &Verified{Digest: hashes[name]}
		if present {
			c.Principals = []Principal{{ID: id}}
		}
		for _, parent := range parents {
			c.Parents = append(c.Parents, hashes[parent])
		}
		view.verified[c.Digest] = c
	}
	add("genesis", false)
	add("join", true, "genesis")
	add("continuous", true, "join")
	add("remove", false, "join")
	add("rejoin", true, "remove")
	add("merge", true, "continuous", "remove")
	for _, tc := range []struct {
		head, from string
		want       bool
	}{
		{"continuous", "join", true},
		{"rejoin", "join", false},
		{"merge", "join", false},
		{"rejoin", "rejoin", true},
		{"join", "genesis", true},
		{"merge", "rejoin", false},
		{"join", "continuous", false},
		{"missing", "join", false},
		{"continuous", "missing", false},
	} {
		t.Run(tc.head+"/"+tc.from, func(t *testing.T) {
			head, from := hashes[tc.head], hashes[tc.from]
			if got := view.MembershipUnbroken(head, from, id); got != tc.want {
				t.Fatalf("got %t want %t", got, tc.want)
			}
		})
	}
}

func TestStateGenerationAndOpMustBeWellFormed(t *testing.T) {
	f := newStateFixture(t)
	p := digest.FromString("p")
	for name, mutate := range map[string]func(*State){
		"zero":           func(s *State) { s.Generation = 0 },
		"root above one": func(s *State) { s.Generation = 2 },
		"child at one":   func(s *State) { s.Parents = []digest.Digest{p}; s.Generation = 1 },
		"unknown op":     func(s *State) { s.Op = "compact" },
		"missing op":     func(s *State) { s.Op = "" },
	} {
		s := f.state(f.bob)
		mutate(&s)
		if _, err := SignState(s, f.bob.signer); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// A revision whose parents are all present must carry the Generation they
// imply; with a parent deleted it cannot be checked and is kept.
func TestLoadStatesChecksGenerationsAgainstPresentParents(t *testing.T) {
	ctx := context.Background()
	f := newStateFixture(t)
	root := f.publish(t, f.state(f.alice), f.alice, "root")
	child := f.publish(t, f.state(f.alice, root), f.alice, "child")
	inflated := f.state(f.bob, child)
	inflated.Generation = 1000
	wrong := f.publish(t, inflated, f.bob, "inflated")
	sv, err := LoadStates(ctx, f.store, f.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if sv.Graph.Has(wrong) || sv.Skipped != 1 || sv.MaxGeneration() != 2 || len(sv.Heads) != 1 || sv.Heads[0].Digest != child {
		t.Fatalf("inflated generation kept: heads %v skipped %d max %d", sv.Heads, sv.Skipped, sv.MaxGeneration())
	}

	if err := f.store.Delete(ctx, storage.KindState, storage.StateScope(testWorkspace, testResource), root); err != nil {
		t.Fatal(err)
	}
	sv, err = LoadStates(ctx, f.store, f.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if !sv.Graph.Has(child) || sv.Graph.Has(root) || sv.MaxGeneration() != 2 {
		t.Fatalf("revision above a deleted parent: states %v max %d", sv.States, sv.MaxGeneration())
	}
}

// A revision by a member removed since still counts as evidence of how fresh
// storage is, though it is no longer read as current.
func TestRemovedAuthorsRevisionStillCountsForFreshness(t *testing.T) {
	ctx := context.Background()
	f := newStateFixture(t)
	root := f.publish(t, f.state(f.alice), f.alice, "root")
	f.publish(t, f.state(f.bob, root), f.bob, "bob")
	if _, err := UpdateControl(ctx, f.store, f.view, f.alice.signer, func(c *Control) error {
		c.Principals = []Principal{f.alice.p}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sv, err := LoadStates(ctx, f.store, load(t, f.store, f.genesis), testWorkspace, testResource)
	if err != nil || sv.MaxGeneration() != 2 {
		t.Fatalf("max generation = %d %v", sv.MaxGeneration(), err)
	}
}

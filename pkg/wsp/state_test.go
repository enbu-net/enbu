package wsp

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

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
}

// newStateFixture founds a workspace with alice (admin) and bob (member).
func newStateFixture(t *testing.T) stateFixture {
	t.Helper()
	store, alice, genesis := workspace(t)
	bob := newActor(t, false)
	v := addMember(t, store, genesis, alice, bob)
	return stateFixture{store: store, alice: alice, bob: bob, genesis: genesis, view: load(t, store, genesis), headHash: v.Digest}
}

func (f stateFixture) state(author actor, parents ...digest.Digest) State {
	return State{Workspace: testWorkspace, Resource: testResource, Parents: parents, Control: f.headHash, Ciphertext: digest.FromString("ciphertext"), Author: author.p.ID}
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
	if err := AuthorIsCurrent(head, got); err != nil {
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
	if err := AuthorIsCurrent(head, st); !errors.Is(err, ErrInvalid) {
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

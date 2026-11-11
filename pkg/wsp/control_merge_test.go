package wsp

import (
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
)

// testDAG builds verified Controls in memory.
type testDAG struct {
	t     *testing.T
	m     map[digest.Digest]*Verified
	blobs map[digest.Digest][]byte
}

func newDAG(t *testing.T, founder actor) (*testDAG, *Verified) {
	t.Helper()
	blob, d := genesisOf(t, founder)
	genesis, err := VerifyGenesis(testWorkspace, blob, d)
	if err != nil {
		t.Fatal(err)
	}
	dag := &testDAG{t: t, m: map[digest.Digest]*Verified{d: genesis}, blobs: map[digest.Digest][]byte{d: blob}}
	return dag, genesis
}

func (d *testDAG) get(x digest.Digest) (*Verified, bool) {
	v, ok := d.m[x]
	return v, ok
}

// child signs and verifies a successor of parent listing principals.
func (d *testDAG) child(parent *Verified, by actor, principals ...Principal) *Verified {
	d.t.Helper()
	blob := nextOf(d.t, parent, by, principals...)
	v, err := VerifyChild([]*Verified{parent}, blob, d.get)
	if err != nil {
		d.t.Fatal(err)
	}
	d.m[v.Digest], d.blobs[v.Digest] = v, blob
	return v
}

// resolve signs a resolution of heads listing principals and verifies it.
func (d *testDAG) resolve(by actor, heads []*Verified, principals ...Principal) (*Verified, error) {
	d.t.Helper()
	ds := make([]digest.Digest, len(heads))
	var h uint64
	for i, p := range heads {
		ds[i] = p.Digest
		h = max(h, p.Height)
	}
	sortDigests(ds)
	blob, err := SignControl(Control{Workspace: testWorkspace, Parents: ds, Height: h + 1, Principals: principals, Author: by.p.ID}, by.signer)
	if err != nil {
		return nil, err
	}
	v, err := VerifyChild(heads, blob, d.get)
	if err != nil {
		return nil, err
	}
	d.m[v.Digest], d.blobs[v.Digest] = v, blob
	return v, nil
}

func (d *testDAG) merge(heads ...*Verified) ([]Principal, error) {
	heads = append([]*Verified(nil), heads...)
	sortVerified(heads)
	return MergePrincipals(heads, d.get)
}

func requireMerge(t *testing.T, got []Principal, err error, want ...Principal) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if w := (Control{Principals: want}).canonical().Principals; !samePrincipals(got, w) {
		t.Fatalf("merged %v, want %v", ids(got), ids(w))
	}
}

func ids(ps []Principal) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.ID.Fingerprint()
		if p.Admin {
			out[i] += "(admin)"
		}
	}
	return out
}

func admin(p Principal) Principal {
	p.Admin = true
	return p
}

func member(p Principal) Principal {
	p.Admin = false
	return p
}

// Two admins approving different devices at once keep both. The intersection
// used to drop them both without telling anyone.
func TestMergeKeepsConcurrentApprovals(t *testing.T) {
	alice, bob, carol, dave := newActor(t, true), newActor(t, true), newActor(t, false), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p)
	a := d.child(base, alice, alice.p, bob.p, carol.p)
	b := d.child(base, bob, alice.p, bob.p, dave.p)
	got, err := d.merge(a, b)
	requireMerge(t, got, err, alice.p, bob.p, carol.p, dave.p)
	if _, err := d.resolve(bob, []*Verified{a, b}, got...); err != nil {
		t.Fatalf("the merge does not verify: %v", err)
	}
}

func TestMergeLetsARemovalAndADemotionWin(t *testing.T) {
	alice, bob, carol, dave := newActor(t, true), newActor(t, true), newActor(t, true), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p, carol.p, dave.p)
	// alice removes dave and demotes carol; bob promotes dave.
	a := d.child(base, alice, alice.p, bob.p, member(carol.p))
	b := d.child(base, bob, alice.p, bob.p, carol.p, admin(dave.p))
	got, err := d.merge(a, b)
	requireMerge(t, got, err, alice.p, bob.p, member(carol.p))
}

func TestMergeKeepsAPromotionAndARecipientChange(t *testing.T) {
	alice, bob, carol, other := newActor(t, true), newActor(t, true), newActor(t, false), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p, carol.p)
	upgraded := carol.p
	upgraded.Recipient = other.p.Recipient
	a := d.child(base, alice, alice.p, bob.p, admin(carol.p))
	b := d.child(base, bob, alice.p, bob.p, upgraded)
	got, err := d.merge(a, b)
	requireMerge(t, got, err, alice.p, bob.p, admin(upgraded))
}

// A principal two branches changed or added differently is left out; an
// admin approves it again.
func TestMergeLeavesOutConflictingChanges(t *testing.T) {
	alice, bob, carol, dave, x, y := newActor(t, true), newActor(t, true), newActor(t, false), newActor(t, false), newActor(t, false), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p, carol.p)
	carolX, carolY := carol.p, carol.p
	carolX.Recipient, carolY.Recipient = x.p.Recipient, y.p.Recipient
	daveX, daveY := dave.p, dave.p
	daveX.Recipient, daveY.Recipient = x.p.Recipient, y.p.Recipient
	a := d.child(base, alice, alice.p, bob.p, carolX, daveX)
	b := d.child(base, bob, alice.p, bob.p, carolY, daveY)
	got, err := d.merge(a, b)
	requireMerge(t, got, err, alice.p, bob.p)
}

// A device added as an admin on one branch and as a member on another joins
// as a member.
func TestMergeAddsAsAMemberWhenTheBranchesDisagree(t *testing.T) {
	alice, bob, carol := newActor(t, true), newActor(t, true), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p)
	a := d.child(base, alice, alice.p, bob.p, admin(carol.p))
	b := d.child(base, bob, alice.p, bob.p, carol.p)
	got, err := d.merge(a, b)
	requireMerge(t, got, err, alice.p, bob.p, carol.p)
}

// An admin removed on one branch still signs children of the Controls that
// listed it. Its branch counts for nothing: it cannot add anyone, even through
// a member it promoted.
func TestMergeDiscardsTheBranchOfARemovedAdmin(t *testing.T) {
	alice, bob, carol, mallory := newActor(t, true), newActor(t, true), newActor(t, false), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p)
	removed := d.child(base, alice, alice.p, carol.p)
	later := d.child(removed, alice, alice.p, admin(carol.p))
	// bob forks from the older Control after its removal and adds mallory.
	forked := d.child(base, bob, alice.p, bob.p, admin(mallory.p))
	got, err := d.merge(later, forked)
	requireMerge(t, got, err, alice.p, admin(carol.p))
	// alice is an admin of both heads and publishes it.
	if _, err := d.resolve(alice, []*Verified{later, forked}, got...); err != nil {
		t.Fatalf("the merge does not verify: %v", err)
	}
	deeper := d.child(forked, mallory, alice.p, bob.p, admin(mallory.p), carol.p)
	got, err = d.merge(later, deeper)
	requireMerge(t, got, err, alice.p, admin(carol.p))
}

// If the removed admin also removes the admin who removed it, the branches
// discard each other and the merge keeps what both heads keep. Here that is
// nobody, so the fork cannot be joined, as before; it does not bring the
// removed admin back.
func TestMergeOfARemovedAdminRemovingItsRemover(t *testing.T) {
	alice, bob, carol, mallory := newActor(t, true), newActor(t, true), newActor(t, false), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p)
	later := d.child(base, alice, alice.p, admin(carol.p))
	forked := d.child(base, bob, bob.p, admin(mallory.p))
	if _, err := d.merge(later, forked); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the merge of a removed admin's counter-removal: %v", err)
	}
}

// Two admins removing each other discard both branches; the merge keeps what
// every head keeps, and an admin of both joins them.
func TestMergeOfMutualRemovalKeepsTheIntersection(t *testing.T) {
	alice, bob, carol, dave := newActor(t, true), newActor(t, true), newActor(t, true), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p, carol.p)
	a := d.child(base, alice, alice.p, carol.p, dave.p)
	b := d.child(base, bob, bob.p, carol.p)
	got, err := d.merge(a, b)
	requireMerge(t, got, err, carol.p)
	if _, err := d.resolve(carol, []*Verified{a, b}, got...); err != nil {
		t.Fatalf("the merge does not verify: %v", err)
	}
}

// A change by an admin that its own branch later removed still counts.
func TestMergeKeepsChangesOfAnAdminRemovedOnItsOwnBranch(t *testing.T) {
	alice, bob, carol, dave, erin := newActor(t, true), newActor(t, true), newActor(t, false), newActor(t, false), newActor(t, false)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p)
	added := d.child(base, bob, alice.p, bob.p, carol.p)
	a := d.child(added, alice, alice.p, carol.p)
	b := d.child(base, alice, alice.p, bob.p, dave.p, erin.p)
	got, err := d.merge(a, b)
	requireMerge(t, got, err, alice.p, carol.p, dave.p, erin.p)
}

func TestMergeFailsWithoutAnAdmin(t *testing.T) {
	alice, bob := newActor(t, true), newActor(t, true)
	d, genesis := newDAG(t, alice)
	base := d.child(genesis, alice, alice.p, bob.p)
	// Each admin demotes itself on its own branch; both branches stand.
	a := d.child(base, alice, member(alice.p), bob.p)
	b := d.child(base, bob, alice.p, member(bob.p))
	if _, err := d.merge(a, b); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a merge without an admin: %v", err)
	}
}

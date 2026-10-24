package wsp

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	digest "github.com/opencontainers/go-digest"
)

func (f stateFixture) compaction(by actor, floor digest.Digest, removed ...digest.Digest) Compaction {
	return Compaction{Workspace: testWorkspace, Resource: testResource, Floor: floor, Removed: removed, Control: f.headHash, Author: by.p.ID}
}

func (f stateFixture) publishCompaction(t *testing.T, c Compaction, by actor) digest.Digest {
	t.Helper()
	blob, err := SignCompaction(c, by.signer)
	if err != nil {
		t.Fatal(err)
	}
	rev := digest.FromBytes(blob)
	if err := f.store.Publish(context.Background(), storage.Object{Kind: storage.KindCompaction, Scope: c.Scope(), Rev: rev, Head: blob}); err != nil {
		t.Fatal(err)
	}
	return rev
}

func TestCompactionNeedsAnAdmin(t *testing.T) {
	f := newStateFixture(t)
	a, b := digest.FromString("a"), digest.FromString("b")
	f.publishCompaction(t, f.compaction(f.alice, a, b), f.alice)
	f.publishCompaction(t, f.compaction(f.bob, a, digest.FromString("c")), f.bob)
	records, err := LoadCompactions(context.Background(), f.store, f.view, testWorkspace, testResource)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Author != f.alice.p.ID {
		t.Fatalf("records = %+v, want only alice's", records)
	}
	// Another resource's records are not this one's.
	other, err := LoadCompactions(context.Background(), f.store, f.view, testWorkspace, "secrets/other")
	if err != nil || len(other) != 0 {
		t.Fatalf("other resource records = %v, %v", other, err)
	}
}

func TestCompactionValidation(t *testing.T) {
	f := newStateFixture(t)
	a, b := digest.FromString("a"), digest.FromString("b")
	for name, c := range map[string]Compaction{
		"nothing removed": f.compaction(f.alice, a),
		"removes floor":   f.compaction(f.alice, a, a),
		"duplicate":       f.compaction(f.alice, a, b, b),
	} {
		if _, err := SignCompaction(c, f.alice.signer); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := SignCompaction(f.compaction(f.bob, a, b), f.alice.signer); !errors.Is(err, ErrInvalid) {
		t.Errorf("signed by someone else: %v", err)
	}
	blob, err := SignCompaction(f.compaction(f.alice, a, b), f.alice.signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCompaction(f.view, testWorkspace, "secrets/other", digest.FromBytes(blob), blob); !errors.Is(err, ErrInvalid) {
		t.Errorf("record of another resource: %v", err)
	}
	if _, err := VerifyCompaction(f.view, testWorkspace, testResource, digest.FromString("x"), blob); !errors.Is(err, ErrInvalid) {
		t.Errorf("record under another name: %v", err)
	}
}

// graphOf builds a graph from revision -> parents.
func graphOf(revs map[string][]string) (*Graph, map[string]digest.Digest) {
	ids := map[string]digest.Digest{}
	for name := range revs {
		ids[name] = digest.FromString(name)
	}
	g := NewGraph()
	for name, parents := range revs {
		var ps []digest.Digest
		for _, p := range parents {
			ps = append(ps, digest.FromString(p))
		}
		g.Add(ids[name], ps)
	}
	return g, ids
}

func TestComputeExcusesThroughLaterCompactions(t *testing.T) {
	// History old <- f1 <- f2 <- head. A first compaction kept f1 and removed
	// old; a second kept f2 and removed f1. A device that accepted old must be
	// excused through both.
	g, _ := graphOf(map[string][]string{"f2": {"f1"}, "head": {"f2"}})
	old, f1, f2 := digest.FromString("old"), digest.FromString("f1"), digest.FromString("f2")
	first := &VerifiedCompaction{Compaction: Compaction{Floor: f1, Removed: []digest.Digest{old}}}
	second := &VerifiedCompaction{Compaction: Compaction{Floor: f2, Removed: []digest.Digest{f1}}}
	c := Compute([]*VerifiedCompaction{first, second}, g)
	if !c.Excuses(old) || !c.Excuses(f1) {
		t.Fatalf("excused = %v", c.Removed)
	}
	if len(c.Floors) != 1 || c.Floors[0] != f2 {
		t.Fatalf("floors = %v", c.Floors)
	}

	// Without the second record, old is listed by a record whose floor is gone.
	if c := Compute([]*VerifiedCompaction{first}, g); c.Excuses(old) {
		t.Fatal("a record whose floor storage does not show excused a revision")
	}
}

func TestAboveFloors(t *testing.T) {
	g, ids := graphOf(map[string][]string{"floor": nil, "head": {"floor"}, "late": {"gone"}})
	c := Compacted{Floors: []digest.Digest{ids["floor"]}}
	if !c.AboveFloors(g, ids["head"]) || !c.AboveFloors(g, ids["floor"]) {
		t.Fatal("revisions kept by the compaction are below its floor")
	}
	if c.AboveFloors(g, ids["late"]) {
		t.Fatal("a revision built on removed history is above the floor")
	}
	if !(Compacted{}).AboveFloors(g, ids["late"]) {
		t.Fatal("without compaction everything is above the floor")
	}
}

func TestCheckpointExcusesCompactedHeads(t *testing.T) {
	cps := OpenCheckpoints(t.TempDir(), testWorkspace, digest.FromString("genesis"))
	g, ids := graphOf(map[string][]string{"old": nil})
	if err := cps.AcceptStates(testResource, g, nil, []digest.Digest{ids["old"]}); err != nil {
		t.Fatal(err)
	}
	later, lids := graphOf(map[string][]string{"head": {"old"}})
	if err := cps.CheckStates(testResource, later, nil); !errors.Is(err, ErrRollback) {
		t.Fatalf("a missing accepted head without a record: %v", err)
	}
	excused := func(d digest.Digest) bool { return d == ids["old"] }
	if err := cps.CheckStates(testResource, later, excused); err != nil {
		t.Fatal(err)
	}
	if err := cps.AcceptStates(testResource, later, excused, []digest.Digest{lids["head"]}); err != nil {
		t.Fatal(err)
	}
	if got, _ := cps.State(testResource); len(got) != 1 || got[0] != lids["head"] {
		t.Fatalf("accepted = %v", got)
	}
}

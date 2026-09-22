package artifact

import (
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestValidateStrongClosure(t *testing.T) {
	t.Parallel()

	child := validResource()
	child.UID = testChildUID
	child.Metadata.Name = "child"
	childRef := sealedFor(child, "child-material", "child-grant")
	root := Revision{
		APIVersion: APIVersion,
		Kind:       KindCollection,
		UID:        testResourceUID,
		Schema:     TypeRef{Group: "example.com", Version: "v1", Kind: "Environment"},
		Metadata:   Metadata{Name: "root"},
		Edges: []Edge{{
			ID:       testEdgeID,
			Name:     "child",
			Relation: MemberRelation(),
			Strength: EdgePinned,
			Target:   child.UID,
			Pinned:   &childRef,
		}},
	}
	rootRef := sealedFor(root, "root-material", "root-grant")
	records := []RevisionRecord{{Ref: rootRef, Value: root}, {Ref: childRef, Value: child}}
	if err := ValidateStrongClosure(rootRef, records); err != nil {
		t.Fatalf("ValidateStrongClosure(valid): %v", err)
	}

	unreachable := validResource()
	unreachable.UID = "88888888-8888-4888-8888-888888888888"
	unreachable.Metadata.Name = "unreachable"
	unreachableRef := sealedFor(unreachable, "unreachable-material", "unreachable-grant")
	withUnreachable := append(append([]RevisionRecord(nil), records...), RevisionRecord{Ref: unreachableRef, Value: unreachable})
	if err := ValidateStrongClosure(rootRef, withUnreachable); !errors.Is(err, ErrUnreachableRevision) {
		t.Fatalf("unreachable closure = %v, want ErrUnreachableRevision", err)
	}

	missing := []RevisionRecord{{Ref: rootRef, Value: root}}
	if err := ValidateStrongClosure(rootRef, missing); !errors.Is(err, ErrMissingPinnedRevision) {
		t.Fatalf("missing child = %v, want ErrMissingPinnedRevision", err)
	}
}

func TestValidateStrongDAGAllowsLogicalCycles(t *testing.T) {
	t.Parallel()

	left := validResource()
	left.UID = testResourceUID
	left.Metadata.Name = "left"
	right := validResource()
	right.UID = testChildUID
	right.Metadata.Name = "right"
	left.Edges = []Edge{{
		ID:       testEdgeID,
		Name:     "right",
		Relation: TypeRef{Group: "example.com", Version: "v1", Kind: "Related"},
		Strength: EdgeLogical,
		Target:   right.UID,
	}}
	right.Edges = []Edge{{
		ID:       "44444444-4444-4444-8444-444444444444",
		Name:     "left",
		Relation: TypeRef{Group: "example.com", Version: "v1", Kind: "Related"},
		Strength: EdgeLogical,
		Target:   left.UID,
	}}
	leftRef := sealedFor(left, "left-material", "left-grant")
	rightRef := sealedFor(right, "right-material", "right-grant")
	if err := ValidateStrongDAG([]RevisionRecord{{Ref: leftRef, Value: left}, {Ref: rightRef, Value: right}}); err != nil {
		t.Fatalf("logical cycle: %v", err)
	}
}

func TestValidateStrongDAGRejectsConflictingUID(t *testing.T) {
	t.Parallel()

	first := validResource()
	second := validResource()
	second.Metadata.Name = "other revision"
	firstRef := sealedFor(first, "first-material", "first-grant")
	secondRef := sealedFor(second, "second-material", "second-grant")
	if err := ValidateStrongDAG([]RevisionRecord{{Ref: firstRef, Value: first}, {Ref: secondRef, Value: second}}); !errors.Is(err, ErrConflictingUID) {
		t.Fatalf("conflicting UID = %v, want ErrConflictingUID", err)
	}
}

func TestStrongCycleDetector(t *testing.T) {
	t.Parallel()

	one := digest.FromString("one")
	two := digest.FromString("two")
	graph := validatedGraph{byDigest: map[digest.Digest]RevisionRecord{
		one: {Value: Revision{Edges: []Edge{{Strength: EdgePinned, Pinned: &SealedRef{Revision: two}}}}},
		two: {Value: Revision{Edges: []Edge{{Strength: EdgePinned, Pinned: &SealedRef{Revision: one}}}}},
	}}
	if err := validateNoStrongCycles(graph); !errors.Is(err, ErrStrongCycle) {
		t.Fatalf("cycle = %v, want ErrStrongCycle", err)
	}
}

package desktop

import (
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

// conflictFixture has alice and bob change KEY at the same time: bob publishes
// while alice is publishing, so both revisions survive and KEY conflicts.
func conflictFixture(t *testing.T) *membersFixture {
	t.Helper()
	f := newMembersFixture(t)
	if err := f.alice.ApproveMember(f.bobDevice); err != nil {
		t.Fatal(err)
	}
	if err := f.alice.AddSecret("", "KEY", "base"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.bob.ListSecrets(""); err != nil {
		t.Fatal(err)
	}
	raced := false
	f.alice.app.Storage = storagetest.Wrap(f.store, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if o.Kind == storage.KindState && !raced {
				raced = true
				if err := f.bob.EditSecret("", "KEY", "bob's"); err != nil {
					t.Error(err)
				}
			}
			return next.Publish(ctx, o)
		},
	})
	if err := f.alice.EditSecret("", "KEY", "alice's"); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestConflictsCanBeListedAndResolvedFromTheDesktop(t *testing.T) {
	f := conflictFixture(t)
	if _, err := f.alice.ListSecrets(""); !apperr.Is(err, apperr.CodeSecretConflict) {
		t.Fatalf("list on a conflict: %v", err)
	}
	set, err := f.alice.ListConflicts("")
	if err != nil || set.Environment != "default" || len(set.Heads) != 2 || len(set.Conflicts) != 1 || set.Conflicts[0].Key != "KEY" {
		t.Fatalf("conflicts: %+v %v", set, err)
	}
	values := map[string]bool{}
	for _, c := range set.Conflicts[0].Candidates {
		values[c.Value] = true
	}
	if !values["alice's"] || !values["bob's"] {
		t.Fatalf("candidates: %+v", set.Conflicts[0].Candidates)
	}
	if err := f.alice.ResolveConflicts("", set.Heads, []ConflictChoice{{Key: "KEY", Value: "bob's"}}); err != nil {
		t.Fatal(err)
	}
	for _, who := range []*Service{f.alice, f.bob} {
		got, err := who.ListSecrets("")
		if err != nil || len(got.Secrets) != 1 || got.Secrets[0].Value != "bob's" {
			t.Fatalf("after resolving: %+v %v", got, err)
		}
	}
	if set, err := f.bob.ListConflicts(""); err != nil || len(set.Conflicts) != 0 {
		t.Fatalf("conflicts after resolving: %+v %v", set, err)
	}
}

func TestResolvingAConflictCanDeleteTheKey(t *testing.T) {
	f := conflictFixture(t)
	set, err := f.bob.ListConflicts("")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.bob.ResolveConflicts("", set.Heads, []ConflictChoice{{Key: "KEY", Delete: true}}); err != nil {
		t.Fatal(err)
	}
	if got, err := f.alice.ListSecrets(""); err != nil || len(got.Secrets) != 0 {
		t.Fatalf("after deleting: %+v %v", got, err)
	}
}

func TestResolvingRefusesStaleHeadsAndDuplicateKeys(t *testing.T) {
	f := conflictFixture(t)
	set, err := f.alice.ListConflicts("")
	if err != nil {
		t.Fatal(err)
	}
	err = f.alice.ResolveConflicts("", set.Heads, []ConflictChoice{{Key: "KEY", Value: "a"}, {Key: "KEY", Value: "b"}})
	if !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("duplicate key: %v", err)
	}
	// A choice made from heads that are no longer the current ones publishes nothing.
	err = f.alice.ResolveConflicts("", set.Heads[:1], []ConflictChoice{{Key: "KEY", Value: "a"}})
	if !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("stale heads: %v", err)
	}
	// Leaving a conflicted key undecided publishes nothing either.
	err = f.alice.ResolveConflicts("", set.Heads, nil)
	if !apperr.Is(err, apperr.CodeSecretConflict) {
		t.Fatalf("nothing decided: %v", err)
	}
	if _, err := f.alice.ListSecrets(""); !apperr.Is(err, apperr.CodeSecretConflict) {
		t.Fatalf("still conflicted: %v", err)
	}
}

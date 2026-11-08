package app

import (
	"context"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

func editTimes(t *testing.T, a *App, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := a.EditSecret(bg, "default", "KEY", "v"+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
}

// A device that accepted a revision the compaction removed reads on: the kept
// head carries a higher Generation than anything it accepted.
func TestCompactionKeepsTheLatestAndOtherDevicesAccept(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if got := listOK(t, bob); got["KEY"] != "v1" { // bob accepts the current head
		t.Fatalf("bob reads %v", got)
	}
	editTimes(t, alice, 4)
	before := len(revisionsOf(t, alice, "default"))

	result, err := alice.CompactHistory(bg, "default", 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept != 2 || result.Removed != before-2 {
		t.Fatalf("result = %+v, want 2 kept of %d", result, before)
	}
	if left := revisionsOf(t, alice, "default"); len(left) != 2 {
		t.Fatalf("revisions left = %d", len(left))
	}
	if got := listOK(t, bob); got["KEY"] != "vd" {
		t.Fatalf("bob after compaction reads %v", got)
	}
	if entries, err := bob.ListHistory(bg, "default"); err != nil || len(entries) != 2 {
		t.Fatalf("history after compaction = %v, %v", entries, err)
	}
	if err := bob.AddSecret(bg, "default", "NEW", "1"); err != nil {
		t.Fatal(err)
	}
	if got := listOK(t, alice); got["NEW"] != "1" || got["KEY"] != "vd" {
		t.Fatalf("alice reads %v", got)
	}
}

// Deleting old revisions needs no record: a device that accepted one of them
// reads on, because the newest revision is still shown.
func TestDeletingOldRevisionsWithoutARecordIsNotARollback(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	listOK(t, bob)
	accepted := revisionsOf(t, bob, "default")
	editTimes(t, alice, 2)
	scope := defaultScope(t, alice)
	for _, d := range accepted {
		if err := alice.Storage.Delete(bg, storage.KindState, scope, d); err != nil {
			t.Fatal(err)
		}
	}
	if got := listOK(t, bob); got["KEY"] != "vb" {
		t.Fatalf("bob reads %v", got)
	}
}

// Hiding the revisions newer than what a device accepted is a rollback.
func TestHidingANewerGenerationIsARollback(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	before := map[digest.Digest]bool{}
	for _, d := range revisionsOf(t, alice, "default") {
		before[d] = true
	}
	editTimes(t, alice, 1)
	listOK(t, bob) // bob accepts the edit
	scope := defaultScope(t, alice)
	for _, d := range revisionsOf(t, alice, "default") {
		if !before[d] {
			if err := alice.Storage.Delete(bg, storage.KindState, scope, d); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := bob.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("error = %v, want rollback", err)
	}
}

func defaultScope(t *testing.T, a *App) string {
	t.Helper()
	s, err := a.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	return storage.StateScope(s.workspace, s.resource("default"))
}

// Two compactions in a row: a device offline across both reads on.
func TestRepeatedCompactions(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	listOK(t, bob)
	editTimes(t, alice, 3)
	if _, err := alice.CompactHistory(bg, "default", 2); err != nil {
		t.Fatal(err)
	}
	editTimes(t, alice, 3)
	if _, err := alice.CompactHistory(bg, "default", 1); err != nil {
		t.Fatal(err)
	}
	if left := revisionsOf(t, alice, "default"); len(left) != 1 {
		t.Fatalf("revisions left = %d", len(left))
	}
	if got := listOK(t, bob); got["KEY"] != "vc" {
		t.Fatalf("bob reads %v", got)
	}
}

// A revision written on top of history that was removed meanwhile shares no
// retained history with the current head: every value they disagree on is a
// conflict rather than silently merged.
func TestARevisionBuiltOnRemovedHistoryConflicts(t *testing.T) {
	alice := newAlice(t)
	old := revisionsOf(t, alice, "default")
	editTimes(t, alice, 3)
	if _, err := alice.CompactHistory(bg, "default", 1); err != nil {
		t.Fatal(err)
	}
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encryptForTest(s, map[string]string{"KEY": "late"})
	if err != nil {
		t.Fatal(err)
	}
	publishRevision(t, alice.Storage, alice, s.workspace, s.resource("default"), s.head.Digest, cipher, old...)
	s.Close()
	set, err := alice.ListConflicts(bg, "default")
	if err != nil || len(set.Conflicts) != 1 || set.Conflicts[0].Key != "KEY" || len(set.Conflicts[0].Candidates) != 2 {
		t.Fatalf("conflicts = %+v, %v", set, err)
	}
}

func TestCompactionChecks(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	if _, err := alice.CompactHistory(bg, "default", 0); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("keep 0: %v", err)
	}
	if _, err := bob.CompactHistory(bg, "default", 1); !apperr.Is(err, apperr.CodeAccessDenied) {
		t.Fatalf("a member compacted: %v", err)
	}
	real := alice.Storage
	alice.Storage = noDelete{real}
	if _, err := alice.CompactHistory(bg, "default", 1); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("a backend that cannot delete: %v", err)
	}
	alice.Storage = real

	// Nothing older than what is kept: nothing to do.
	n := len(revisionsOf(t, alice, "default"))
	result, err := alice.CompactHistory(bg, "default", n+5)
	if err != nil || result.Removed != 0 || result.Kept != n {
		t.Fatalf("result = %+v, %v", result, err)
	}

	// Concurrent heads are merged first.
	publishConcurrent(t, alice, bob, map[string]string{"A": "1"}, map[string]string{"B": "1"})
	if _, err := alice.CompactHistory(bg, "default", 1); !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("compacting concurrent heads: %v", err)
	}
}

// publishConcurrent publishes one revision by each of a and b on top of the
// current head, leaving two heads.
func publishConcurrent(t *testing.T, a, b *App, fromA, fromB map[string]string) {
	t.Helper()
	s, err := a.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resource := s.resource("default")
	read, err := s.readResource(bg, resource, nil, false)
	if err != nil || len(read.heads) != 1 {
		t.Fatalf("read before the concurrent writes: %v", err)
	}
	head := read.heads[0].Digest
	for i, w := range []struct {
		who     *App
		secrets map[string]string
	}{{a, fromA}, {b, fromB}} {
		secrets := map[string]string{}
		for k, v := range read.secrets {
			secrets[k] = v
		}
		for k, v := range w.secrets {
			secrets[k] = v
		}
		cipher, err := encryptForTest(s, secrets)
		if err != nil {
			t.Fatal(err)
		}
		publishRevisionAt(t, a.Storage, w.who, s.workspace, resource, s.head.Digest, cipher, 1700000000+int64(i), head)
	}
}

// Heads written on top of the floor after a compaction merge like before: the
// floor is their merge base, and history ends at the parents it names.
func TestConcurrentHeadsMergeAfterCompaction(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	editTimes(t, alice, 3)
	if _, err := alice.CompactHistory(bg, "default", 1); err != nil {
		t.Fatal(err)
	}
	publishConcurrent(t, alice, bob, map[string]string{"A": "1"}, map[string]string{"B": "2"})
	for name, who := range map[string]*App{"alice": alice, "bob": bob} {
		if got := listOK(t, who); got["A"] != "1" || got["B"] != "2" || got["KEY"] != "vc" {
			t.Fatalf("%s reads %v", name, got)
		}
	}
	if err := alice.SyncSecrets(bg, "default"); err != nil {
		t.Fatal(err)
	}
	if got := listOK(t, bob); got["A"] != "1" || got["B"] != "2" {
		t.Fatalf("bob after sync reads %v", got)
	}
}

// Revisions that fail verification are deleted too.
func TestCompactionDeletesUnverifiableRevisions(t *testing.T) {
	alice := newAlice(t)
	editTimes(t, alice, 1)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	scope := storage.StateScope(s.workspace, s.resource("default"))
	s.Close()
	junk := storagetest.Object(storage.KindState, scope, "junk", "cipher")
	if err := alice.Storage.Publish(bg, junk); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.CompactHistory(bg, "default", 1); err != nil {
		t.Fatal(err)
	}
	for _, d := range revisionsOf(t, alice, "default") {
		if d == junk.Rev {
			t.Fatal("junk revision kept")
		}
	}
}

// Only revisions storage serves and verification rejects are deleted as junk.
// One that cannot be fetched right now, and one published after the read, stay.
func TestCompactionKeepsRevisionsItCannotJudge(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	editTimes(t, alice, 2)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	resource := s.resource("default")
	scope := storage.StateScope(s.workspace, resource)
	read, err := s.readResource(bg, resource, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := encryptForTest(s, map[string]string{"KEY": "vb", "LATE": "1"})
	if err != nil {
		t.Fatal(err)
	}
	control := s.head.Digest
	s.Close()
	unreachable := storagetest.Object(storage.KindState, scope, "unreachable", "cipher")
	if err := alice.Storage.Publish(bg, unreachable); err != nil {
		t.Fatal(err)
	}

	real := alice.Storage
	var late digest.Digest
	listings := 0
	alice.Storage = storagetest.Wrap(real, storagetest.Hooks{
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			if rev == unreachable.Rev {
				return nil, storage.ErrNotFound
			}
			return next.FetchHead(ctx, kind, scope, rev)
		},
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if kind == storage.KindState {
				if listings++; listings == 2 { // the compaction's own listing, after its read
					late = publishRevision(t, real, bob, read.heads[0].Workspace, resource, control, cipher, read.heads[0].Digest)
				}
			}
			return next.Discover(ctx, kind, scope)
		},
	})
	if _, err := alice.CompactHistory(bg, "default", 1); err != nil {
		t.Fatal(err)
	}
	alice.Storage = real
	left := map[digest.Digest]bool{}
	for _, d := range revisionsOf(t, alice, "default") {
		left[d] = true
	}
	if late == "" || !left[late] || !left[unreachable.Rev] {
		t.Fatalf("late %s kept %v, unreachable kept %v", late, left[late], left[unreachable.Rev])
	}
	if got := listOK(t, alice); got["LATE"] != "1" {
		t.Fatalf("reads %v", got)
	}
}

// A re-encryption is hidden while its parent is in the history. Once
// compaction removes that parent, the re-encryption is listed instead.
func TestCompactionShowsAReencryptionWhoseParentIsGone(t *testing.T) {
	a := newAlice(t)
	if err := a.SyncSecrets(bg, "default"); err != nil {
		t.Fatal(err)
	}
	before, err := a.ListHistory(bg, "default")
	if err != nil || len(before) != 1 {
		t.Fatalf("history before compaction = %v, %v", before, err)
	}
	if _, err := a.CompactHistory(bg, "default", 1); err != nil {
		t.Fatal(err)
	}
	after, err := a.ListHistory(bg, "default")
	if err != nil || len(after) != 1 || after[0].Tag == before[0].Tag {
		t.Fatalf("history after compaction = %v, %v; before = %v", after, err, before)
	}
}

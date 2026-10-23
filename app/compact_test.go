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

func compactionRecords(t *testing.T, a *App) []digest.Digest {
	t.Helper()
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	revs, err := a.Storage.Discover(bg, storage.KindCompaction, storage.StateScope(cfg.WorkspaceID, cfg.Resource("default")))
	if err != nil {
		t.Fatal(err)
	}
	return revs
}

// A device that accepted a revision the compaction removed reads on: the
// signed record excuses the revision storage no longer shows.
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
	if len(compactionRecords(t, alice)) != 1 {
		t.Fatal("no compaction record")
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

// The record is what makes a deletion acceptable: deleting the same revisions
// without one is a rollback to a device that accepted one of them.
func TestDeletingWithoutARecordIsARollback(t *testing.T) {
	alice := newAlice(t)
	bob := approved(t, alice)
	listOK(t, bob)
	accepted := revisionsOf(t, bob, "default")
	editTimes(t, alice, 2)
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	scope := storage.StateScope(s.workspace, s.resource("default"))
	s.Close()
	for _, d := range accepted {
		if err := alice.Storage.Delete(bg, storage.KindState, scope, d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := bob.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("error = %v, want rollback", err)
	}
}

// Two compactions in a row: a device offline across both is excused through
// the second record, which removed the first one's floor.
func TestRepeatedCompactionsChainTheirRecords(t *testing.T) {
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

// A revision written on top of history that was removed meanwhile cannot be
// merged: its merge base is gone. It is set aside so it does not block reads.
func TestARevisionBuiltOnRemovedHistoryIsSetAside(t *testing.T) {
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
	if got := listOK(t, alice); got["KEY"] != "vc" {
		t.Fatalf("reads %v", got)
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
	if len(compactionRecords(t, alice)) != 0 {
		t.Fatal("a compaction that removed nothing published a record")
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
// floor is their merge base, and the parents it names below itself are excused.
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

// Revisions that fail verification are deleted too, without a record.
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

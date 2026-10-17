package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

type retryEvents struct {
	recordingEvents
	retries [][2]int
}

func (e *retryEvents) OnConflictRetry(attempt, limit int) {
	e.retries = append(e.retries, [2]int{attempt, limit})
}

// sharedWorkspace is a workspace with two members who see the same storage.
func sharedWorkspace(t *testing.T) (alice, bob *App) {
	t.Helper()
	alice = newAlice(t)
	bob = approved(t, alice)
	return alice, bob
}

func listOK(t *testing.T, a *App) map[string]string {
	t.Helper()
	got, err := a.ListSecrets(bg, "default")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// raceOnPublish makes other write while the first State publish of a is in
// flight: after a's last look at the storage, before its revision lands. This
// is the window an update used to be lost in.
func raceOnPublish(a *App, other func()) {
	done := false
	a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if o.Kind == storage.KindState && !done {
				done = true
				other()
			}
			return next.Publish(ctx, o)
		},
	})
}

// The point of the design: two successful concurrent writes both survive.
func TestConcurrentWritesOfDifferentKeysBothSurvive(t *testing.T) {
	alice, bob := sharedWorkspace(t)
	raceOnPublish(alice, func() {
		if err := bob.AddSecret(bg, "default", "FROM_BOB", "b"); err != nil {
			t.Error(err)
		}
	})
	if err := alice.AddSecret(bg, "default", "FROM_ALICE", "a"); err != nil {
		t.Fatal(err)
	}
	for name, who := range map[string]*App{"alice": alice, "bob": bob} {
		got := listOK(t, who)
		if got["FROM_ALICE"] != "a" || got["FROM_BOB"] != "b" || got["KEY"] != "v1" {
			t.Fatalf("%s sees %v", name, got)
		}
	}
	// The next write merges the two heads into one revision.
	if err := alice.AddSecret(bg, "default", "LATER", "x"); err != nil {
		t.Fatal(err)
	}
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readResource(bg, "default", nil, false)
	if err != nil || len(read.heads) != 1 || len(read.heads[0].Parents) != 2 {
		t.Fatalf("heads did not converge: %+v %v", read, err)
	}
}

// A head that appears while the user is editing is merged in the same revision.
func TestHeadThatAppearsWhileEditingIsMergedBeforePublishing(t *testing.T) {
	alice, bob := sharedWorkspace(t)
	events := &retryEvents{}
	alice.Events = events
	raced := false
	err := alice.changeSecret(bg, "default", "add", func(secrets map[string]string) error {
		if !raced {
			raced = true
			if err := bob.AddSecret(bg, "default", "FROM_BOB", "b"); err != nil {
				t.Error(err)
			}
		}
		secrets["FROM_ALICE"] = "a"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.retries) != 1 {
		t.Fatalf("retries = %v, want one", events.retries)
	}
	got := listOK(t, alice)
	if got["FROM_ALICE"] != "a" || got["FROM_BOB"] != "b" {
		t.Fatalf("secrets = %v", got)
	}
}

func TestConcurrentEditsOfOneKeyStopForAPersonToChoose(t *testing.T) {
	alice, bob := sharedWorkspace(t)
	raceOnPublish(alice, func() {
		if err := bob.EditSecret(bg, "default", "KEY", "bob's"); err != nil {
			t.Error(err)
		}
	})
	// Both writes succeed; nothing is lost and nothing is chosen silently.
	if err := alice.EditSecret(bg, "default", "KEY", "alice's"); err != nil {
		t.Fatal(err)
	}
	for _, who := range []*App{alice, bob} {
		if _, err := who.ListSecrets(bg, "default"); !apperr.Is(err, apperr.CodeSecretConflict) {
			t.Fatalf("list on a conflict: %v", err)
		}
		if _, _, _, err := who.PullSecrets(bg, "default"); !apperr.Is(err, apperr.CodeSecretConflict) {
			t.Fatalf("pull on a conflict: %v", err)
		}
		if err := who.AddSecret(bg, "default", "OTHER", "x"); !apperr.Is(err, apperr.CodeSecretConflict) {
			t.Fatalf("write on a conflict: %v", err)
		}
	}
	set, err := bob.ListConflicts(bg, "default")
	if err != nil || len(set.Conflicts) != 1 || set.Conflicts[0].Key != "KEY" || len(set.Conflicts[0].Candidates) != 2 {
		t.Fatalf("conflicts = %+v %v", set, err)
	}
	conflicts := set.Conflicts
	values := map[string]bool{}
	for _, c := range conflicts[0].Candidates {
		values[c.Value] = true
	}
	if !values["alice's"] || !values["bob's"] {
		t.Fatalf("candidates lost a value: %+v", conflicts[0].Candidates)
	}

	// Settling every conflict publishes a merge revision.
	if err := bob.ResolveSecrets(bg, "default", set.Heads, map[string]SecretChoice{}); !apperr.Is(err, apperr.CodeSecretConflict) {
		t.Fatalf("resolving nothing: %v", err)
	}
	if err := bob.ResolveSecrets(bg, "default", set.Heads, map[string]SecretChoice{"KEY": {Value: "alice's"}}); err != nil {
		t.Fatal(err)
	}
	for _, who := range []*App{alice, bob} {
		if got := listOK(t, who); got["KEY"] != "alice's" {
			t.Fatalf("after resolving: %v", got)
		}
	}
}

func TestResolveCanDeleteAndLateWritesStillConflict(t *testing.T) {
	alice, bob := sharedWorkspace(t)
	raceOnPublish(alice, func() {
		if err := bob.DeleteSecret(bg, "default", "KEY"); err != nil {
			t.Error(err)
		}
	})
	if err := alice.EditSecret(bg, "default", "KEY", "kept"); err != nil {
		t.Fatal(err)
	}
	set, err := alice.ListConflicts(bg, "default")
	if err != nil || len(set.Conflicts) != 1 {
		t.Fatalf("delete against edit: %+v %v", set, err)
	}
	deleted := false
	for _, c := range set.Conflicts[0].Candidates {
		deleted = deleted || c.Deleted
	}
	if !deleted {
		t.Fatal("the deletion is not offered as a candidate")
	}
	if err := alice.ResolveSecrets(bg, "default", set.Heads, map[string]SecretChoice{"KEY": {Delete: true}}); err != nil {
		t.Fatal(err)
	}
	if got := listOK(t, bob); len(got) != 0 {
		t.Fatalf("after deleting: %v", got)
	}
}

// A listing that does not show a revision yet makes a fork, not a lost update.
func TestStaleListingMakesAForkNotALostUpdate(t *testing.T) {
	alice, bob := sharedWorkspace(t)
	if err := bob.AddSecret(bg, "default", "FROM_BOB", "b"); err != nil {
		t.Fatal(err)
	}
	// Alice's storage view does not list bob's revision yet.
	real := alice.Storage
	bs, err := bob.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := bs.loadResource(bg, "default")
	bs.Close()
	if err != nil || len(sv.Heads) != 1 {
		t.Fatalf("bob's view: %v", err)
	}
	newest := sv.Heads[0].Digest
	alice.Storage = hide(real, newest)
	if err := alice.AddSecret(bg, "default", "FROM_ALICE", "a"); err != nil {
		t.Fatal(err)
	}
	alice.Storage = real
	for _, who := range []*App{alice, bob} {
		got := listOK(t, who)
		if got["FROM_ALICE"] != "a" || got["FROM_BOB"] != "b" {
			t.Fatalf("after the listing caught up: %v", got)
		}
	}
}

func TestSyncSecretsCancellation(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "value"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.SyncSecrets(ctx, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
}

func TestSecretsChangingEveryAttemptEventuallyReportsAConflict(t *testing.T) {
	alice, bob := sharedWorkspace(t)
	n := 0
	err := alice.changeSecret(bg, "default", "add", func(secrets map[string]string) error {
		n++
		if err := bob.AddSecret(bg, "default", "BUSY"+string(rune('a'+n)), "x"); err != nil {
			t.Error(err)
		}
		secrets["MINE"] = "1"
		return nil
	})
	if !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("a storage that changes on every attempt: %v", err)
	}
	if n != maxRetries {
		t.Fatalf("attempts = %d, want %d", n, maxRetries)
	}
}

var _ = digest.Digest("")

// A choice is made against the values the person saw. If another value shows up
// before they decide, it must not be swept away by a choice made without it.
func TestResolveRefusesWhenAValueAppearedAfterTheListing(t *testing.T) {
	alice, bob := sharedWorkspace(t)
	raceOnPublish(alice, func() {
		if err := bob.EditSecret(bg, "default", "KEY", "bob's"); err != nil {
			t.Error(err)
		}
	})
	if err := alice.EditSecret(bg, "default", "KEY", "alice's"); err != nil {
		t.Fatal(err)
	}
	set, err := alice.ListConflicts(bg, "default")
	if err != nil || len(set.Conflicts) != 1 || set.ID == "" {
		t.Fatalf("listing: %+v %v", set, err)
	}

	// A third value for KEY arrives, written from the same base as the others.
	s, err := alice.openSession(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	read, err := s.readResource(bg, "default", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	third, err := encryptForTest(s, map[string]string{"KEY": "carol's"})
	if err != nil {
		t.Fatal(err)
	}
	baseRev := read.heads[0].Parents
	publishRevision(t, alice.Storage, bob, s.workspace, s.resource("default"), s.head.Digest, third, baseRev...)

	err = alice.ResolveSecrets(bg, "default", set.Heads, map[string]SecretChoice{"KEY": {Value: "alice's"}})
	if !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("resolving against a stale listing: %v", err)
	}
	fresh, err := alice.ListConflicts(bg, "default")
	if err != nil || fresh.ID == set.ID || len(fresh.Conflicts[0].Candidates) != 3 {
		t.Fatalf("the new value is not offered: %+v %v", fresh, err)
	}
	if err := alice.ResolveSecrets(bg, "default", fresh.Heads, map[string]SecretChoice{"KEY": {Value: "alice's"}}); err != nil {
		t.Fatalf("resolving the listing that was shown: %v", err)
	}
}

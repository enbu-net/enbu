package app

import (
	"context"
	"io"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// storageCalls counts what an operation asks of storage. Heads are fetched
// concurrently, so the counters are atomic.
type storageCalls struct {
	heads, blobs, stateListings atomic.Int64
}

func countCalls(a *App) *storageCalls {
	c := &storageCalls{}
	a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			c.heads.Add(1)
			return next.FetchHead(ctx, kind, scope, rev)
		},
		OpenBlob: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
			c.blobs.Add(1)
			return next.OpenBlob(ctx, kind, scope, rev, index)
		},
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if kind == storage.KindState {
				c.stateListings.Add(1)
			}
			return next.Discover(ctx, kind, scope)
		},
	})
	return c
}

func TestReadsUseCachedHeads(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1", "B": "2", "C": "3"})
	calls := countCalls(a)
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]string{"A": "1", "B": "2", "C": "3"}) {
		t.Fatalf("secrets = %v", got)
	}
	// Every head was fetched while writing; only the current ciphertext is read.
	if calls.heads.Load() != 0 || calls.blobs.Load() != 1 {
		t.Fatalf("heads = %d, blobs = %d; want 0 and 1", calls.heads.Load(), calls.blobs.Load())
	}
}

// A write lists the resource to read it and once more just before publishing,
// then checks storage once more before advancing its checkpoint.
func TestWriteChecksStorageAfterPublishing(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	calls := countCalls(a)
	if err := a.AddSecret(context.Background(), "default", "B", "2"); err != nil {
		t.Fatal(err)
	}
	if calls.stateListings.Load() != 3 {
		t.Fatalf("state listings = %d, want 3", calls.stateListings.Load())
	}
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil || got["B"] != "2" {
		t.Fatalf("secrets = %v, %v", got, err)
	}
}

func TestHistoryDecryptsOnlyWhatIsNew(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	if err := a.EditSecret(ctx, "default", "A", "2"); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncSecrets(ctx, "default"); err != nil { // repeats the content
		t.Fatal(err)
	}
	calls := countCalls(a)
	cold, err := a.ListHistory(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(cold) != 2 || calls.blobs.Load() != 3 {
		t.Fatalf("entries = %d, blobs = %d; want 2 entries from 3 revisions", len(cold), calls.blobs.Load())
	}

	calls.blobs.Store(0)
	warm, err := a.ListHistory(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(warm, cold) || calls.blobs.Load() != 0 {
		t.Fatalf("warm listing = %v with %d blobs, want %v with none", warm, calls.blobs.Load(), cold)
	}

	calls.blobs.Store(0)
	diff, err := a.DiffHistory(ctx, "default", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(diff.Modified, []string{"A"}) || calls.blobs.Load() != 2 {
		t.Fatalf("diff = %+v with %d blobs, want A modified from 2 blobs", diff, calls.blobs.Load())
	}

	if err := a.AddSecret(ctx, "default", "B", "3"); err != nil {
		t.Fatal(err)
	}
	calls.blobs.Store(0)
	after, err := a.ListHistory(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	// The new revision and the parent it is compared with.
	if len(after) != 3 || calls.blobs.Load() != 2 {
		t.Fatalf("entries = %d, blobs = %d; want 3 entries from 2 blobs", len(after), calls.blobs.Load())
	}
}

// The index only remembers flags; a revision it names that is no longer in the
// verified history is not listed.
func TestHistoryIndexCannotAddRevisions(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	s, err := a.openSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resource := s.resource("default")
	index := a.openHistoryIndex(s, resource)
	s.Close()
	forged := digest.FromString("not a revision")
	index.save(map[digest.Digest]historyFlags{forged: {Readable: true}},
		map[digest.Digest]*wsp.VerifiedState{forged: nil})
	entries, err := a.ListHistory(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Tag == forged.Encoded() {
		t.Fatalf("entries = %v", entries)
	}
}

// Another process of the same device can accept a newer head while a write is
// publishing. Recording what this write published then needs a fresh look at
// storage, or the checkpoint would see a rollback.
func TestWriteAcceptsWhatAnotherProcessAcceptedMeanwhile(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	twin := *a // same storage, keys and checkpoint, as a second process
	real := a.Storage
	raceOnPublish(a, func() {
		if err := twin.AddSecret(context.Background(), "default", "B", "2"); err != nil {
			t.Fatal(err)
		}
	})
	if err := a.AddSecret(context.Background(), "default", "C", "3"); err != nil {
		t.Fatal(err)
	}
	a.Storage = real
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil || got["B"] != "2" || got["C"] != "3" {
		t.Fatalf("secrets = %v, %v", got, err)
	}
}

// Another process of the same device can accept a head after this read listed
// storage. The read fetches that head by name instead of calling it a rollback.
func TestReadAcceptsWhatAnotherProcessAcceptedAfterListing(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	twin := *a // same storage, keys and checkpoint, as a second process
	real := a.Storage
	done := false
	a.Storage = storagetest.Wrap(real, storagetest.Hooks{
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			revs, err := next.Discover(ctx, kind, scope)
			if kind == storage.KindState && !done {
				done = true
				if err := twin.AddSecret(ctx, "default", "B", "2"); err != nil {
					t.Fatal(err)
				}
			}
			return revs, err
		},
	})
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil || got["A"] != "1" || got["B"] != "2" {
		t.Fatalf("secrets = %v, %v", got, err)
	}
}

// Another process can also accept a head while this read decrypts, before it
// records what it read. The read then reads again rather than reporting a
// rollback or recording heads older than the accepted one.
func TestReadRecordsAfterAnotherProcessAcceptedMeanwhile(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	twin := *a // same storage, keys and checkpoint, as a second process
	real := a.Storage
	done := false
	a.Storage = storagetest.Wrap(real, storagetest.Hooks{
		OpenBlob: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
			if !done {
				done = true
				if err := twin.AddSecret(ctx, "default", "B", "2"); err != nil {
					t.Fatal(err)
				}
			}
			return next.OpenBlob(ctx, kind, scope, rev, index)
		},
	})
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil || got["B"] != "2" {
		t.Fatalf("secrets = %v, %v", got, err)
	}
}

func TestWriteDoesNotForgetARevisionDeletedDuringPublish(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	s, err := a.openSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resource := s.resource("default")
	accepted, err := s.cps.State(resource)
	if err != nil {
		t.Fatal(err)
	}
	scope := storage.StateScope(s.workspace, resource)
	s.Close()
	real := a.Storage
	raceOnPublish(a, func() {
		for _, d := range accepted {
			if err := real.Delete(context.Background(), storage.KindState, scope, d); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err := a.AddSecret(context.Background(), "default", "B", "2"); !apperr.Is(err, apperr.CodeRollback) {
		t.Fatalf("write error = %v, want rollback", err)
	}
	s, err = a.openSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after, err := s.cps.State(resource)
	if err != nil || !reflect.DeepEqual(after, accepted) {
		t.Fatalf("checkpoint = %v, %v; want %v", after, err, accepted)
	}
}

func TestHistoryIndexChangesWithLoadedIdentities(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	s, err := a.openSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resource := s.resource("default")
	original := a.openHistoryIndex(s, resource)
	s.ids = append(s.ids, mustKeyPair(t).Identity)
	retained := a.openHistoryIndex(s, resource)
	if retained.path == original.path {
		t.Fatal("adding a retained identity reused the original flags")
	}
	s.ids[0], s.ids[1] = s.ids[1], s.ids[0]
	if a.openHistoryIndex(s, resource).path != retained.path {
		t.Fatal("identity order changed the cache key")
	}
	s.ids = s.ids[1:]
	if a.openHistoryIndex(s, resource).path != original.path {
		t.Fatal("removing the retained identity did not restore the original cache key")
	}
}

// Local flags are display hints trusted as written. They cannot add revisions,
// but editing them can hide entries and change the numeric history indices.
func TestHistoryIndexTrustsLocalDisplayFlags(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	entries, err := a.ListHistory(context.Background(), "default")
	if err != nil || len(entries) != 1 {
		t.Fatalf("history = %v, %v", entries, err)
	}
	s, err := a.openSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	index := a.openHistoryIndex(s, s.resource("default"))
	s.Close()
	d := digest.NewDigestFromEncoded(digest.SHA256, entries[0].Tag)
	index.save(map[digest.Digest]historyFlags{d: {}}, map[digest.Digest]*wsp.VerifiedState{d: nil})
	entries, err = a.ListHistory(context.Background(), "default")
	if err != nil || len(entries) != 0 {
		t.Fatalf("edited history = %v, %v", entries, err)
	}
}

func TestHistoryRepeatBecomesVisibleWhenParentDisappears(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	if err := a.SyncSecrets(context.Background(), "default"); err != nil {
		t.Fatal(err)
	}
	entries, err := a.ListHistory(context.Background(), "default")
	if err != nil || len(entries) != 1 {
		t.Fatalf("history = %v, %v", entries, err)
	}
	s, err := a.openSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	scope := storage.StateScope(s.workspace, s.resource("default"))
	s.Close()
	old := digest.NewDigestFromEncoded(digest.SHA256, entries[0].Tag)
	if err := a.Storage.Delete(context.Background(), storage.KindState, scope, old); err != nil {
		t.Fatal(err)
	}
	warm, err := a.ListHistory(context.Background(), "default")
	if err != nil || len(warm) != 1 || warm[0].Tag == entries[0].Tag {
		t.Fatalf("warm history = %v, %v", warm, err)
	}
	a.CacheDir = t.TempDir()
	cold, err := a.ListHistory(context.Background(), "default")
	if err != nil || !reflect.DeepEqual(cold, warm) {
		t.Fatalf("cold = %v, %v; warm = %v", cold, err, warm)
	}
}

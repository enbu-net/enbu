package app

import (
	"context"
	"io"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
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
		OpenPayload: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
			c.blobs.Add(1)
			return next.OpenPayload(ctx, kind, scope, rev)
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

// Listing history decrypts nothing: readability comes from the Control a
// revision names and re-encryptions from its Op. Only a diff decrypts.
func TestHistoryListingDecryptsNothing(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	if err := a.EditSecret(ctx, "default", "A", "2"); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncSecrets(ctx, "default"); err != nil { // repeats the content
		t.Fatal(err)
	}
	calls := countCalls(a)
	entries, err := a.ListHistory(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || calls.blobs.Load() != 0 {
		t.Fatalf("entries = %d, blobs = %d; want 2 entries from 3 revisions without a blob", len(entries), calls.blobs.Load())
	}
	diff, err := a.DiffHistory(ctx, "default", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(diff.Modified, []string{"A"}) || calls.blobs.Load() != 2 {
		t.Fatalf("diff = %+v with %d blobs, want A modified from 2 blobs", diff, calls.blobs.Load())
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
// storage. The read lists storage again instead of calling it a rollback.
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
		OpenPayload: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
			if !done {
				done = true
				if err := twin.AddSecret(ctx, "default", "B", "2"); err != nil {
					t.Fatal(err)
				}
			}
			return next.OpenPayload(ctx, kind, scope, rev)
		},
	})
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil || got["B"] != "2" {
		t.Fatalf("secrets = %v, %v", got, err)
	}
}

// Old revisions may be deleted while a write publishes; that is no rollback,
// and the checkpoint records the new revision's Generation.
func TestWriteSurvivesOldRevisionsDeletedDuringPublish(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	s, err := a.openSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resource := s.resource("default")
	scope := storage.StateScope(s.workspace, resource)
	s.Close()
	old := revisionsOf(t, a, "default")
	real := a.Storage
	raceOnPublish(a, func() {
		for _, d := range old {
			if err := real.Delete(context.Background(), storage.KindState, scope, d); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err := a.AddSecret(context.Background(), "default", "B", "2"); err != nil {
		t.Fatalf("write error = %v", err)
	}
	a.Storage = real
	s, err = a.openSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, err := s.cps.Generation(resource); err != nil || got != 2 {
		t.Fatalf("checkpoint = %v, %v; want generation 2", got, err)
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
	after, err := a.ListHistory(context.Background(), "default")
	if err != nil || len(after) != 1 || after[0].Tag == entries[0].Tag {
		t.Fatalf("history = %v, %v", after, err)
	}
}

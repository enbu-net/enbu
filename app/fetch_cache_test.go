package app

import (
	"context"
	"io"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// storageCalls counts what an operation asks of storage.
type storageCalls struct {
	heads, blobs, stateListings int
}

func countCalls(a *App) *storageCalls {
	c := &storageCalls{}
	a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{
		FetchHead: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
			c.heads++
			return next.FetchHead(ctx, kind, scope, rev)
		},
		OpenBlob: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
			c.blobs++
			return next.OpenBlob(ctx, kind, scope, rev, index)
		},
		Discover: func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error) {
			if kind == storage.KindState {
				c.stateListings++
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
	if calls.heads != 0 || calls.blobs != 1 {
		t.Fatalf("heads = %d, blobs = %d; want 0 and 1", calls.heads, calls.blobs)
	}
}

// A write lists the resource to read it and once more just before publishing,
// and records what it published without listing a third time.
func TestWriteListsStatesTwice(t *testing.T) {
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"A": "1"})
	calls := countCalls(a)
	if err := a.AddSecret(context.Background(), "default", "B", "2"); err != nil {
		t.Fatal(err)
	}
	if calls.stateListings != 2 {
		t.Fatalf("state listings = %d, want 2", calls.stateListings)
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
	if len(cold) != 2 || calls.blobs != 3 {
		t.Fatalf("entries = %d, blobs = %d; want 2 entries from 3 revisions", len(cold), calls.blobs)
	}

	calls.blobs = 0
	warm, err := a.ListHistory(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(warm, cold) || calls.blobs != 0 {
		t.Fatalf("warm listing = %v with %d blobs, want %v with none", warm, calls.blobs, cold)
	}

	calls.blobs = 0
	diff, err := a.DiffHistory(ctx, "default", 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(diff.Modified, []string{"A"}) || calls.blobs != 2 {
		t.Fatalf("diff = %+v with %d blobs, want A modified from 2 blobs", diff, calls.blobs)
	}

	if err := a.AddSecret(ctx, "default", "B", "3"); err != nil {
		t.Fatal(err)
	}
	calls.blobs = 0
	after, err := a.ListHistory(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	// The new revision and the parent it is compared with.
	if len(after) != 3 || calls.blobs != 2 {
		t.Fatalf("entries = %d, blobs = %d; want 3 entries from 2 blobs", len(after), calls.blobs)
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

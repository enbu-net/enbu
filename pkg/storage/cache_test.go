package storage_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

type countingStore struct {
	storage.Store
	fetches int
}

func (c *countingStore) FetchHead(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
	c.fetches++
	return c.Store.FetchHead(ctx, kind, scope, rev)
}

func publishControl(t *testing.T, s storage.Store, head string) digest.Digest {
	t.Helper()
	o := storage.Object{Kind: storage.KindControl, Rev: digest.FromString(head), Head: []byte(head)}
	if err := s.Publish(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	return o.Rev
}

func TestHeadCacheServesListedRevisions(t *testing.T) {
	ctx := context.Background()
	mem := storagetest.NewMemory()
	rev := publishControl(t, mem, "control one")
	dir := t.TempDir()

	first := &countingStore{Store: mem}
	if _, err := storage.WithHeadCache(first, dir).FetchHead(ctx, storage.KindControl, "", rev); err != nil {
		t.Fatal(err)
	}
	if first.fetches != 1 {
		t.Fatalf("fetches = %d, want 1", first.fetches)
	}

	// A later run lists the revision and reads it from the cache.
	later := &countingStore{Store: mem}
	cached := storage.WithHeadCache(later, dir)
	if _, err := cached.Discover(ctx, storage.KindControl, ""); err != nil {
		t.Fatal(err)
	}
	head, err := cached.FetchHead(ctx, storage.KindControl, "", rev)
	if err != nil || string(head) != "control one" {
		t.Fatalf("head = %q, %v", head, err)
	}
	if later.fetches != 0 {
		t.Fatalf("fetches = %d, want 0 for a cached, listed revision", later.fetches)
	}
}

// The cache never shows what storage no longer lists: a revision that was
// deleted elsewhere is asked of storage, which reports it gone.
func TestHeadCacheDoesNotResurrectDeletedRevisions(t *testing.T) {
	ctx := context.Background()
	mem := storagetest.NewMemory()
	rev := publishControl(t, mem, "control one")
	dir := t.TempDir()
	if _, err := storage.WithHeadCache(mem, dir).FetchHead(ctx, storage.KindControl, "", rev); err != nil {
		t.Fatal(err)
	}
	if err := mem.Delete(ctx, storage.KindControl, "", rev); err != nil {
		t.Fatal(err)
	}
	cached := storage.WithHeadCache(mem, dir)
	revs, err := cached.Discover(ctx, storage.KindControl, "")
	if err != nil || len(revs) != 0 {
		t.Fatalf("revs = %v, %v", revs, err)
	}
	if _, err := cached.FetchHead(ctx, storage.KindControl, "", rev); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("error = %v, want not found", err)
	}
}

func TestHeadCacheRefetchesDamagedEntries(t *testing.T) {
	ctx := context.Background()
	mem := storagetest.NewMemory()
	rev := publishControl(t, mem, "control one")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, rev.Encoded()), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	counting := &countingStore{Store: mem}
	cached := storage.WithHeadCache(counting, dir)
	if _, err := cached.Discover(ctx, storage.KindControl, ""); err != nil {
		t.Fatal(err)
	}
	head, err := cached.FetchHead(ctx, storage.KindControl, "", rev)
	if err != nil || string(head) != "control one" || counting.fetches != 1 {
		t.Fatalf("head = %q, %v, fetches = %d", head, err, counting.fetches)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, rev.Encoded())); string(b) != "control one" {
		t.Fatalf("cache file = %q, want the fetched head", b)
	}
}

func TestHeadCacheDeleteRemovesEntry(t *testing.T) {
	ctx := context.Background()
	mem := storagetest.NewMemory()
	rev := publishControl(t, mem, "control one")
	dir := t.TempDir()
	cached := storage.WithHeadCache(mem, dir)
	if _, err := cached.FetchHead(ctx, storage.KindControl, "", rev); err != nil {
		t.Fatal(err)
	}
	if err := cached.Delete(ctx, storage.KindControl, "", rev); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, rev.Encoded())); !os.IsNotExist(err) {
		t.Fatalf("cache entry still present: %v", err)
	}
}

func TestHeadCacheRejectsInvalidRefs(t *testing.T) {
	cached := storage.WithHeadCache(storagetest.NewMemory(), t.TempDir())
	if _, err := cached.FetchHead(context.Background(), storage.KindControl, "", "sha256:../../x"); err == nil {
		t.Fatal("an invalid digest was accepted")
	}
}

func TestHeadCacheKeepsPublishedHeads(t *testing.T) {
	ctx := context.Background()
	counting := &countingStore{Store: storagetest.NewMemory()}
	cached := storage.WithHeadCache(counting, t.TempDir())
	rev := publishControl(t, cached, "control one")
	if _, err := cached.Discover(ctx, storage.KindControl, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := cached.FetchHead(ctx, storage.KindControl, "", rev); err != nil || counting.fetches != 0 {
		t.Fatalf("fetches = %d, %v; want the published head from the cache", counting.fetches, err)
	}
}

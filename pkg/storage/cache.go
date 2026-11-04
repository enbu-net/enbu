package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/opencontainers/go-digest"
)

// headCache keeps the heads it fetched in a local directory. A head is named by
// its digest and never changes, so a cached copy that still matches its digest
// is the same object storage holds; the cache needs no trust and no expiry.
//
// It only answers for revisions that the latest listing of their scope showed.
// What storage shows is still decided by storage: a revision that was deleted,
// or never listed, is fetched from the backend like before, so a cache entry
// never brings back a revision storage no longer has.
type headCache struct {
	Store
	dir string

	mu     sync.Mutex
	listed map[listing]map[digest.Digest]bool
}

type listing struct {
	kind  Kind
	scope string
}

// WithHeadCache returns s with its heads cached under dir. Blobs are not
// cached: they are read only for the few revisions whose content is used.
func WithHeadCache(s Store, dir string) Store {
	return &headCache{Store: s, dir: dir, listed: map[listing]map[digest.Digest]bool{}}
}

func (c *headCache) path(rev digest.Digest) string {
	// The digest was validated, so its hex form is a safe file name.
	return filepath.Join(c.dir, rev.Encoded())
}

func (c *headCache) Discover(ctx context.Context, kind Kind, scope string) ([]digest.Digest, error) {
	revs, err := c.Store.Discover(ctx, kind, scope)
	if err != nil {
		return nil, err
	}
	set := make(map[digest.Digest]bool, len(revs))
	for _, r := range revs {
		set[r] = true
	}
	c.mu.Lock()
	c.listed[listing{kind, scope}] = set
	c.mu.Unlock()
	return revs, nil
}

func (c *headCache) wasListed(kind Kind, scope string, rev digest.Digest) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.listed[listing{kind, scope}][rev]
}

func (c *headCache) FetchHead(ctx context.Context, kind Kind, scope string, rev digest.Digest) ([]byte, error) {
	if err := validateRef(kind, scope, rev); err != nil {
		return nil, err
	}
	if c.wasListed(kind, scope, rev) {
		if head, ok := c.read(rev); ok {
			return head, nil
		}
	}
	head, err := c.Store.FetchHead(ctx, kind, scope, rev)
	if err != nil {
		return nil, err
	}
	c.write(rev, head)
	return head, nil
}

// read returns a cached head that still matches its digest. Anything else is
// treated as absent and removed, so a damaged file costs one fetch.
func (c *headCache) read(rev digest.Digest) ([]byte, bool) {
	head, err := os.ReadFile(c.path(rev))
	if err != nil {
		return nil, false
	}
	if len(head) == 0 || len(head) > MaxHeadBytes || digest.FromBytes(head) != rev {
		_ = os.Remove(c.path(rev))
		return nil, false
	}
	return head, true
}

// write stores a head. It is best effort: a cache that cannot be written only
// means the next run fetches the head again.
func (c *headCache) write(rev digest.Digest, head []byte) {
	if digest.FromBytes(head) != rev {
		return
	}
	if _, err := os.Stat(c.path(rev)); err == nil {
		return
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(c.dir, ".head-*")
	if err != nil {
		return
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(head)
	if err = errors.Join(err, tmp.Close()); err != nil {
		return
	}
	_ = os.Rename(tmp.Name(), c.path(rev))
}

// Publish keeps the head of what this device published, which it reads next.
func (c *headCache) Publish(ctx context.Context, o Object) error {
	if err := c.Store.Publish(ctx, o); err != nil {
		return err
	}
	c.write(o.Rev, o.Head)
	return nil
}

func (c *headCache) Delete(ctx context.Context, kind Kind, scope string, rev digest.Digest) error {
	err := c.Store.Delete(ctx, kind, scope, rev)
	if err == nil || errors.Is(err, ErrNotFound) {
		_ = os.Remove(c.path(rev))
		c.mu.Lock()
		delete(c.listed[listing{kind, scope}], rev)
		c.mu.Unlock()
	}
	return err
}

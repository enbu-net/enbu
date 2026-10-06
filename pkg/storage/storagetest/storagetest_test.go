package storagetest

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
)

type countingObjects struct {
	Objects
	gets, puts []string
}

func (c *countingObjects) Get(ctx context.Context, key string) ([]byte, storage.Version, error) {
	c.gets = append(c.gets, key)
	return c.Objects.Get(ctx, key)
}

func (c *countingObjects) Put(ctx context.Context, key string, data []byte, v storage.Version) error {
	c.puts = append(c.puts, key)
	return c.Objects.Put(ctx, key, data, v)
}

// Wrap must intercept ref traffic while still resolving blobs that were only
// ever written to the base store, which FromObjects cannot do.
func TestWrapInterceptsRefsAndSharesBlobs(t *testing.T) {
	ctx := context.Background()
	base := NewMemory()
	ciphertext, err := base.Blobs.Put(ctx, strings.NewReader("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	spy := &countingObjects{Objects: ToObjects(base)}
	wrapped := Wrap(base, spy)

	if err := wrapped.Refs.Put(ctx, "state", ciphertext, ""); err != nil {
		t.Fatal(err)
	}
	got, _, err := wrapped.Refs.Get(ctx, "state")
	if err != nil || got != ciphertext {
		t.Fatalf("ref = %s %v", got, err)
	}
	if len(spy.puts) != 1 || spy.puts[0] != "state" || len(spy.gets) != 1 {
		t.Fatalf("ref traffic was not seen: puts=%v gets=%v", spy.puts, spy.gets)
	}
	for _, s := range []*storage.Store{wrapped, base} {
		rc, err := s.Blobs.Open(ctx, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(data) != "ciphertext" {
			t.Fatalf("blob = %q", data)
		}
	}
	// A ref written through the wrapper is visible in the base store.
	if baseRef, _, err := base.Refs.Get(ctx, "state"); err != nil || baseRef != ciphertext {
		t.Fatalf("base ref = %s %v", baseRef, err)
	}
}

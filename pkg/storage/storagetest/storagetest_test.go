package storagetest

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

func TestHooksInterceptAndPassThrough(t *testing.T) {
	ctx := context.Background()
	base := NewMemory()
	boom := errors.New("boom")
	var published int
	wrapped := Wrap(base, Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			published++
			if published == 1 {
				return boom
			}
			return next.Publish(ctx, o)
		},
		Discover: func(context.Context, storage.Store, storage.Kind, string) ([]digest.Digest, error) {
			return nil, nil // stale listing
		},
	})
	o := Object(storage.KindControl, "", "head")
	if err := wrapped.Publish(ctx, o); !errors.Is(err, boom) {
		t.Fatalf("first publish: %v", err)
	}
	if err := wrapped.Publish(ctx, o); err != nil {
		t.Fatal(err)
	}
	if revs, _ := wrapped.Discover(ctx, storage.KindControl, ""); len(revs) != 0 {
		t.Fatal("hook did not hide the revision")
	}
	if revs, _ := base.Discover(ctx, storage.KindControl, ""); len(revs) != 1 {
		t.Fatal("the base store lost the revision")
	}
	if _, err := wrapped.FetchHead(ctx, o.Kind, o.Scope, o.Rev); err != nil {
		t.Fatalf("fetch passes through: %v", err)
	}
}

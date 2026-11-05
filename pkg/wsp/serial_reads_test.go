package wsp

import (
	"context"
	"errors"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
	"reflect"
	"testing"
)

func TestSerialHeadReadsPreserveOrderAndMissingSemantics(t *testing.T) {
	memory := storagetest.NewMemory()
	scope := storage.StateScope("ws", "resource")
	var revs []digest.Digest
	for _, name := range []string{"third", "first", "second"} {
		o := storagetest.Object(storage.KindState, scope, name, "ciphertext")
		if err := memory.Publish(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		revs = append(revs, o.Rev)
	}
	revs = append(revs, digest.FromString("absent"))
	var observed []digest.Digest
	store := storagetest.Wrap(memory, storagetest.Hooks{FetchHead: func(ctx context.Context, next storage.Store, k storage.Kind, s string, r digest.Digest) ([]byte, error) {
		observed = append(observed, r)
		return next.FetchHead(ctx, k, s, r)
	}})
	result, err := prefetchHeads(WithSerialHeadReads(context.Background()), store, scope, revs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed, revs) {
		t.Fatalf("external read order changed: %v", observed)
	}
	for i, rev := range revs {
		if i == 3 {
			if !errors.Is(result[rev].err, storage.ErrNotFound) {
				t.Fatal("missing head not retained")
			}
		} else if result[rev].err != nil || digest.FromBytes(result[rev].head) != rev {
			t.Fatalf("bad head: %+v", result[rev])
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prefetchHeads(WithSerialHeadReads(ctx), store, scope, revs); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

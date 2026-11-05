package wsp

import (
	"context"
	"errors"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
	"io"
	"reflect"
	"sync/atomic"
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

func TestHeadReadTerminalFailureAbortsInBothModes(t *testing.T) {
	for _, serial := range []bool{false, true} {
		t.Run(map[bool]string{false: "parallel", true: "serial"}[serial], func(t *testing.T) {
			var calls atomic.Int32
			sentinel := io.ErrClosedPipe
			store := storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{FetchHead: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) ([]byte, error) {
				calls.Add(1)
				return nil, sentinel
			}})
			ctx := context.Background()
			if serial {
				ctx = WithSerialHeadReads(ctx)
			}
			got, err := prefetchHeads(ctx, store, storage.StateScope("ws", "resource"), []digest.Digest{digest.FromString("a"), digest.FromString("b")})
			if got != nil || !errors.Is(err, sentinel) {
				t.Fatalf("terminal failure was masked: %v %v", got, err)
			}
			if serial && calls.Load() != 1 {
				t.Fatal("serial fetch continued after terminal error")
			}
		})
	}
}
func TestCorruptHeadIsRetainedInBothModes(t *testing.T) {
	for _, serial := range []bool{false, true} {
		store := storagetest.Wrap(storagetest.NewMemory(), storagetest.Hooks{FetchHead: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) ([]byte, error) {
			return nil, storage.ErrCorrupt
		}})
		ctx := context.Background()
		if serial {
			ctx = WithSerialHeadReads(ctx)
		}
		rev := digest.FromString("corrupt")
		got, err := prefetchHeads(ctx, store, storage.StateScope("ws", "resource"), []digest.Digest{rev})
		if err != nil || !errors.Is(got[rev].err, storage.ErrCorrupt) {
			t.Fatalf("corruption became terminal: %v %v", got, err)
		}
	}
}

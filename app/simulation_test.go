package app

import (
	"context"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
	"io"
	"testing"
)

// Missing bytes of an acknowledged revision must never be classified as an
// uncreated environment: mutations would otherwise publish an empty replacement.
func TestMissingCiphertextNeverBecomesEmptyEnvironment(t *testing.T) {
	a := newAlice(t)
	before := revisionsOf(t, a, "default")
	a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{OpenBlob: func(context.Context, storage.Store, storage.Kind, string, digest.Digest, int) (io.ReadCloser, error) {
		return nil, storage.ErrNotFound
	}})
	if _, e := a.ListSecrets(bg, "default"); !apperr.Is(e, apperr.CodeRollback) {
		t.Fatalf("read: %v", e)
	}
	if e := a.AddSecret(bg, "default", "NEW", "value"); !apperr.Is(e, apperr.CodeRollback) {
		t.Fatalf("write: %v", e)
	}
	if got := revisionsOf(t, a, "default"); len(got) != len(before) {
		t.Fatalf("published replacement: %v", got)
	}
}
func TestMissingAcceptedHeadsNeverBecomeEmptyEnvironment(t *testing.T) {
	a := newAlice(t)
	if _, e := a.ListSecrets(bg, "default"); e != nil {
		t.Fatal(e)
	}
	a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{FetchHead: func(ctx context.Context, s storage.Store, k storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
		if k == storage.KindState {
			return nil, storage.ErrNotFound
		}
		return s.FetchHead(ctx, k, scope, rev)
	}, Discover: func(ctx context.Context, s storage.Store, k storage.Kind, scope string) ([]digest.Digest, error) {
		if k == storage.KindState {
			return nil, nil
		}
		return s.Discover(ctx, k, scope)
	}})
	if _, e := a.ListSecrets(bg, "default"); !apperr.Is(e, apperr.CodeRollback) {
		t.Fatalf("read: %v", e)
	}
}

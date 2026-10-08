package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

// vanishing makes Publish of a State fail with ErrNotFound the first n times,
// as when a registry GC drops a blob before the manifest that names it is read back.
func vanishing(base storage.Store, n int) (storage.Store, *int) {
	published := 0
	return storagetest.Wrap(base, storagetest.Hooks{
		Publish: func(ctx context.Context, next storage.Store, o storage.Object) error {
			if o.Kind == storage.KindState && n > 0 {
				n--
				published++
				return storage.ErrNotFound
			}
			return next.Publish(ctx, o)
		},
	}), &published
}

func TestChangeSecretRetriesWhenBlobVanishesBeforeReadBack(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "original"})
	a.Storage, _ = vanishing(a.Storage, 1)

	if err := a.AddSecret(ctx, "default", "NEW", "value"); err != nil {
		t.Fatal(err)
	}
	secrets, err := a.ListSecrets(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("secrets = %v, want KEY and NEW", secrets)
	}
}

func TestChangeSecretDoesNotReportVanishedBlobAsMissingArtifact(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "original"})
	a.Storage, _ = vanishing(a.Storage, 100)

	err := a.AddSecret(ctx, "default", "NEW", "value")
	if err == nil {
		t.Fatal("expected error")
	}
	if IsNotFoundError(err) || errors.Is(err, storage.ErrNotFound) && IsNotFoundError(err) {
		t.Fatalf("error must not look like a missing environment: %v", err)
	}
}

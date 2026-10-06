package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// vanishingRefs fails Put with ErrNotFound the first n times for the secrets ref.
type vanishingRefs struct {
	storage.Refs
	remaining int
	puts      int
}

func (r *vanishingRefs) Put(ctx context.Context, name string, target digest.Digest, expected storage.Version) error {
	if name == secretsTag("default") && r.remaining > 0 {
		r.remaining--
		r.puts++
		return storage.ErrNotFound
	}
	return r.Refs.Put(ctx, name, target, expected)
}

func TestChangeSecretRetriesWhenBlobVanishesBeforeRefUpdate(t *testing.T) {
	ctx := context.Background()
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), map[string]string{"KEY": "original"})
	refs := &vanishingRefs{Refs: a.Storage.Refs, remaining: 1}
	a.Storage = &storage.Store{Blobs: a.Storage.Blobs, Refs: refs}

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
	a.Storage = &storage.Store{Blobs: a.Storage.Blobs, Refs: &vanishingRefs{Refs: a.Storage.Refs, remaining: 100}}

	err := a.AddSecret(ctx, "default", "NEW", "value")
	if err == nil {
		t.Fatal("expected error")
	}
	if IsNotFoundError(err) || errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("error must not look like a missing ref: %v", err)
	}
}

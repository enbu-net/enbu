package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// putRef stores data as an immutable blob, then points the named ref at it.
func putRef(ctx context.Context, store *storage.Store, name string, data []byte, expected storage.Version) error {
	d, err := store.Blobs.Put(ctx, bytes.NewReader(data))
	if err != nil {
		return err
	}
	return store.Refs.Put(ctx, name, d, expected)
}

// getRef returns the blob a ref points at, and the ref's version.
func getRef(ctx context.Context, store *storage.Store, name string) ([]byte, storage.Version, error) {
	d, version, err := store.Refs.Get(ctx, name)
	if err != nil {
		return nil, "", err
	}
	data, err := readBlob(ctx, store, d)
	if errors.Is(err, storage.ErrNotFound) {
		// A missing blob behind an existing ref is corruption, not an absent ref.
		return nil, "", fmt.Errorf("ref %s points to missing blob %s", name, d)
	}
	return data, version, err
}

func readBlob(ctx context.Context, store *storage.Store, d digest.Digest) ([]byte, error) {
	rc, err := store.Blobs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(rc)
}

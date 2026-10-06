// Package storagetest provides in-memory storage for tests.
package storagetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// Objects is a flat key-to-bytes view of a Store, convenient for fakes that
// inject failures or custom versions. Put with an empty version means create only.
type Objects interface {
	Get(ctx context.Context, key string) ([]byte, storage.Version, error)
	Put(ctx context.Context, key string, data []byte, expected storage.Version) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *storage.Store { return FromObjects(&memory{data: map[string][]byte{}}) }

// FromObjects exposes o as a Store. Blobs live in memory; every ref read or
// write goes through o with the blob bytes.
func FromObjects(o Objects) *storage.Store {
	b := &blobs{data: map[digest.Digest][]byte{}}
	return &storage.Store{Blobs: b, Refs: &refs{o: o, blobs: b}}
}

// Wrap exposes o as the refs of a Store that shares base's blobs. Use it to
// intercept ref reads and writes of base without losing the blobs the refs
// point at, which FromObjects would not know about.
func Wrap(base *storage.Store, o Objects) *storage.Store {
	return &storage.Store{Blobs: base.Blobs, Refs: &refs{o: o, blobs: base.Blobs}}
}

// ToObjects exposes s as Objects.
func ToObjects(s *storage.Store) Objects { return &view{s} }

type blobs struct {
	mu   sync.RWMutex
	data map[digest.Digest][]byte
}

func (b *blobs) Put(ctx context.Context, r io.Reader) (digest.Digest, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(r, storage.MaxPayloadBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > storage.MaxPayloadBytes {
		return "", storage.ErrTooLarge
	}
	if len(data) == 0 {
		return "", storage.ErrEmptyBlob
	}
	d := digest.FromBytes(data)
	b.mu.Lock()
	b.data[d] = data
	b.mu.Unlock()
	return d, nil
}

func (b *blobs) Open(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	data, ok := b.data[d]
	b.mu.RUnlock()
	if !ok {
		return nil, storage.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type refs struct {
	o     Objects
	blobs storage.Blobs
}

func (r *refs) Get(ctx context.Context, name string) (digest.Digest, storage.Version, error) {
	data, v, err := r.o.Get(ctx, name)
	if err != nil {
		return "", "", err
	}
	d, err := r.blobs.Put(ctx, bytes.NewReader(data))
	return d, v, err
}

func (r *refs) Put(ctx context.Context, name string, target digest.Digest, expected storage.Version) error {
	rc, err := r.blobs.Open(ctx, target)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	return r.o.Put(ctx, name, data, expected)
}

func (r *refs) List(ctx context.Context, prefix string) ([]string, error) {
	return r.o.List(ctx, prefix)
}

type view struct{ s *storage.Store }

func (v *view) Get(ctx context.Context, key string) ([]byte, storage.Version, error) {
	d, version, err := v.s.Refs.Get(ctx, key)
	if err != nil {
		return nil, "", err
	}
	rc, err := v.s.Blobs.Open(ctx, d)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	return data, version, err
}

func (v *view) Put(ctx context.Context, key string, data []byte, expected storage.Version) error {
	d, err := v.s.Blobs.Put(ctx, bytes.NewReader(data))
	if err != nil {
		return err
	}
	return v.s.Refs.Put(ctx, key, d, expected)
}

func (v *view) List(ctx context.Context, prefix string) ([]string, error) {
	return v.s.Refs.List(ctx, prefix)
}

type memory struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func version(data []byte) storage.Version {
	return storage.Version(fmt.Sprintf("sha256:%x", sha256.Sum256(data)))
}

func (m *memory) Get(_ context.Context, key string) ([]byte, storage.Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.data[key]
	if !ok {
		return nil, "", storage.ErrNotFound
	}
	return append([]byte(nil), data...), version(data), nil
}

func (m *memory) Put(_ context.Context, key string, data []byte, expected storage.Version) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var current storage.Version
	if old, ok := m.data[key]; ok {
		current = version(old)
	}
	if current != expected {
		return storage.ErrConflict
	}
	m.data[key] = append([]byte(nil), data...)
	return nil
}

func (m *memory) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for key := range m.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

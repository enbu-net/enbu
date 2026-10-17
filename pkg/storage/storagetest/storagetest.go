// Package storagetest provides an in-memory Store, fault injection, and the
// contract every storage backend must satisfy.
package storagetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
)

// Memory is an in-memory Store.
type Memory struct {
	mu   sync.RWMutex
	objs map[string]storage.Object
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory { return &Memory{objs: map[string]storage.Object{}} }

func clone(o storage.Object) storage.Object {
	o.Head = append([]byte(nil), o.Head...)
	o.Blobs = nil
	return o
}

func cloneAll(o storage.Object, src storage.Object) storage.Object {
	o = clone(o)
	for _, b := range src.Blobs {
		o.Blobs = append(o.Blobs, append([]byte(nil), b...))
	}
	return o
}

func sameObject(a, b storage.Object) bool {
	if !bytes.Equal(a.Head, b.Head) || len(a.Blobs) != len(b.Blobs) {
		return false
	}
	for i := range a.Blobs {
		if !bytes.Equal(a.Blobs[i], b.Blobs[i]) {
			return false
		}
	}
	return true
}

func (m *Memory) Capabilities() storage.Capabilities {
	return storage.Capabilities{PhysicalDelete: true}
}

func (m *Memory) Publish(ctx context.Context, o storage.Object) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := storage.ValidateObject(o); err != nil {
		return err
	}
	name, err := storage.Name(o.Kind, o.Scope, o.Rev)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.objs[name]; ok {
		if sameObject(old, o) {
			return nil
		}
		return fmt.Errorf("%w: %s already holds different content", storage.ErrCorrupt, name)
	}
	m.objs[name] = cloneAll(o, o)
	return nil
}

func (m *Memory) get(kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
	name, err := storage.Name(kind, scope, rev)
	if err != nil {
		return storage.Object{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.objs[name]
	if !ok {
		return storage.Object{}, storage.ErrNotFound
	}
	return o, nil
}

func (m *Memory) FetchHead(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o, err := m.get(kind, scope, rev)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), o.Head...), nil
}

func (m *Memory) OpenBlob(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o, err := m.get(kind, scope, rev)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(o.Blobs) {
		return nil, fmt.Errorf("%w: no blob %d", storage.ErrNotFound, index)
	}
	return io.NopCloser(bytes.NewReader(o.Blobs[index])), nil
}

func (m *Memory) Discover(ctx context.Context, kind storage.Kind, scope string) ([]digest.Digest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var revs []digest.Digest
	for _, o := range m.objs {
		if o.Kind == kind && o.Scope == scope {
			revs = append(revs, o.Rev)
		}
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	return revs, nil
}

func (m *Memory) Delete(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) error {
	name, err := storage.Name(kind, scope, rev)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objs[name]; !ok {
		return storage.ErrNotFound
	}
	delete(m.objs, name)
	return nil
}

// Hooks intercepts a Store to inject failures, stale listings or tampering.
// A nil hook passes the call through.
type Hooks struct {
	Publish   func(ctx context.Context, next storage.Store, o storage.Object) error
	FetchHead func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error)
	OpenBlob  func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error)
	Discover  func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error)
	Delete    func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) error
}

type hooked struct {
	storage.Store
	h Hooks
}

// Wrap returns s with the hooks applied.
func Wrap(s storage.Store, h Hooks) storage.Store { return hooked{s, h} }

func (w hooked) Publish(ctx context.Context, o storage.Object) error {
	if w.h.Publish != nil {
		return w.h.Publish(ctx, w.Store, o)
	}
	return w.Store.Publish(ctx, o)
}

func (w hooked) FetchHead(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error) {
	if w.h.FetchHead != nil {
		return w.h.FetchHead(ctx, w.Store, kind, scope, rev)
	}
	return w.Store.FetchHead(ctx, kind, scope, rev)
}

func (w hooked) OpenBlob(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
	if w.h.OpenBlob != nil {
		return w.h.OpenBlob(ctx, w.Store, kind, scope, rev, index)
	}
	return w.Store.OpenBlob(ctx, kind, scope, rev, index)
}

func (w hooked) Discover(ctx context.Context, kind storage.Kind, scope string) ([]digest.Digest, error) {
	if w.h.Discover != nil {
		return w.h.Discover(ctx, w.Store, kind, scope)
	}
	return w.Store.Discover(ctx, kind, scope)
}

func (w hooked) Delete(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) error {
	if w.h.Delete != nil {
		return w.h.Delete(ctx, w.Store, kind, scope, rev)
	}
	return w.Store.Delete(ctx, kind, scope, rev)
}

// Object builds a valid object whose revision is the digest of head, with the
// given blobs attached.
func Object(kind storage.Kind, scope string, head string, blobs ...string) storage.Object {
	o := storage.Object{Kind: kind, Scope: scope, Rev: digest.FromString(head), Head: []byte(head)}
	for _, b := range blobs {
		o.Blobs = append(o.Blobs, []byte(b))
	}
	return o
}

// Scope returns a valid state scope derived from name.
func Scope(name string) string { return storage.StateScope("workspace", name) }

// Contract checks the behavior every backend must provide.
func Contract(t *testing.T, s storage.Store) {
	t.Helper()
	ctx := context.Background()
	scope, other := Scope("secrets/dev"), Scope("secrets/prod")

	state := Object(storage.KindState, scope, "head-state-1", "ciphertext-1")
	control := Object(storage.KindControl, "", "head-control-1")
	request := Object(storage.KindRequest, "", "head-request-1")
	multi := Object(storage.KindState, scope, "head-multi", "first blob", "second blob", strings.Repeat("x", 100000))
	for _, o := range []storage.Object{state, control, request, multi} {
		if err := s.Publish(ctx, o); err != nil {
			t.Fatalf("publish %s: %v", o.Kind, err)
		}
		if err := s.Publish(ctx, o); err != nil {
			t.Fatalf("publish %s again must be idempotent: %v", o.Kind, err)
		}
		head, err := s.FetchHead(ctx, o.Kind, o.Scope, o.Rev)
		if err != nil || !bytes.Equal(head, o.Head) {
			t.Fatalf("head of %s: %v", o.Kind, err)
		}
		for i, want := range o.Blobs {
			got, err := storage.ReadBlob(ctx, s, o.Kind, o.Scope, o.Rev, i, storage.MaxPayloadBytes)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("blob %d of %s: %v", i, o.Kind, err)
			}
		}
		if _, err := s.OpenBlob(ctx, o.Kind, o.Scope, o.Rev, len(o.Blobs)); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("a blob that is not there: %v", err)
		}
		if _, err := s.OpenBlob(ctx, o.Kind, o.Scope, o.Rev, -1); err == nil {
			t.Fatal("a negative blob index was accepted")
		}
	}

	// A name holds one content. The same head with other blobs is rejected.
	forged := state
	forged.Blobs = [][]byte{[]byte("other ciphertext")}
	if err := s.Publish(ctx, forged); err == nil || !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("republishing different content: %v", err)
	}

	// Discover is scoped by kind and scope.
	state2 := Object(storage.KindState, scope, "head-state-2", "ciphertext-2")
	elsewhere := Object(storage.KindState, other, "head-state-3", "ciphertext-3")
	for _, o := range []storage.Object{state2, elsewhere} {
		if err := s.Publish(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	revs, err := s.Discover(ctx, storage.KindState, scope)
	if err != nil {
		t.Fatal(err)
	}
	if want := sortedRevs(state.Rev, state2.Rev, multi.Rev); !equalRevs(revs, want) {
		t.Fatalf("discover state = %v, want %v", revs, want)
	}
	if revs, err := s.Discover(ctx, storage.KindControl, ""); err != nil || !equalRevs(revs, []digest.Digest{control.Rev}) {
		t.Fatalf("discover control = %v %v", revs, err)
	}
	if revs, err := s.Discover(ctx, storage.KindState, Scope("secrets/none")); err != nil || len(revs) != 0 {
		t.Fatalf("discover empty scope = %v %v", revs, err)
	}

	// Missing and invalid references.
	if _, err := s.FetchHead(ctx, storage.KindState, scope, digest.FromString("missing")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := s.OpenBlob(ctx, storage.KindState, scope, digest.FromString("missing"), 0); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing blob: %v", err)
	}
	if _, err := s.FetchHead(ctx, storage.KindState, "../escape", state.Rev); err == nil {
		t.Fatal("invalid scope accepted")
	}
	if _, err := s.FetchHead(ctx, storage.KindControl, "", "sha256:xyz"); err == nil {
		t.Fatal("invalid digest accepted")
	}
	bad := state
	bad.Rev = digest.FromString("something else")
	if err := s.Publish(ctx, bad); err == nil {
		t.Fatal("object whose revision is not the digest of its head was published")
	}
	if err := s.Publish(ctx, Object(storage.KindControl, "", "head-empty-blob", "")); err == nil {
		t.Fatal("an empty blob was published")
	}

	// Concurrent writers never overwrite each other.
	var wg sync.WaitGroup
	var objs []storage.Object
	for i := 0; i < 8; i++ {
		objs = append(objs, Object(storage.KindState, other, fmt.Sprintf("concurrent-%d", i), "cipher"))
	}
	errs := make([]error, len(objs))
	for i := range objs {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = s.Publish(ctx, objs[i]) }()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent publish %d: %v", i, err)
		}
	}
	got, err := s.Discover(ctx, storage.KindState, other)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[digest.Digest]bool{}
	for _, r := range got {
		seen[r] = true
	}
	for _, o := range objs {
		if !seen[o.Rev] {
			t.Fatalf("concurrent revision %s is not discoverable", o.Rev)
		}
	}

	// Delete follows the declared capability.
	err = s.Delete(ctx, storage.KindState, scope, state2.Rev)
	if s.Capabilities().PhysicalDelete {
		if err != nil {
			t.Fatalf("delete: %v", err)
		}
		if _, err := s.FetchHead(ctx, storage.KindState, scope, state2.Rev); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("fetch after delete: %v", err)
		}
	} else if !errors.Is(err, storage.ErrUnsupported) {
		t.Fatalf("delete without capability: %v", err)
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Discover(cctx, storage.KindState, scope); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled discover: %v", err)
	}
}

func sortedRevs(revs ...digest.Digest) []digest.Digest {
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	return revs
}

func equalRevs(a, b []digest.Digest) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

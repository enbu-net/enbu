// Package storagetest provides an in-memory Store, fault injection, and the
// contract every storage backend must satisfy.
package storagetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
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
	o.Signed = append([]byte(nil), o.Signed...)
	o.Cipher = append([]byte(nil), o.Cipher...)
	return o
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
		if bytes.Equal(old.Signed, o.Signed) && bytes.Equal(old.Cipher, o.Cipher) {
			return nil
		}
		return fmt.Errorf("%w: %s already holds different content", storage.ErrCorrupt, name)
	}
	m.objs[name] = clone(o)
	return nil
}

func (m *Memory) Fetch(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
	if err := ctx.Err(); err != nil {
		return storage.Object{}, err
	}
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
	return clone(o), nil
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
	Publish  func(ctx context.Context, next storage.Store, o storage.Object) error
	Fetch    func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error)
	Discover func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error)
	Delete   func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) error
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

func (w hooked) Fetch(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) (storage.Object, error) {
	if w.h.Fetch != nil {
		return w.h.Fetch(ctx, w.Store, kind, scope, rev)
	}
	return w.Store.Fetch(ctx, kind, scope, rev)
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

// Object builds a valid object whose revision is the digest of signed.
func Object(kind storage.Kind, scope string, signed, cipher string) storage.Object {
	return storage.Object{Kind: kind, Scope: scope, Rev: digest.FromString(signed), Signed: []byte(signed), Cipher: []byte(cipher)}
}

// Scope returns a valid state scope derived from name.
func Scope(name string) string { return storage.StateScope("workspace", name) }

// Contract checks the behavior every backend must provide.
func Contract(t *testing.T, s storage.Store) {
	t.Helper()
	ctx := context.Background()
	scope, other := Scope("secrets/dev"), Scope("secrets/prod")

	state := Object(storage.KindState, scope, "signed-state-1", "ciphertext-1")
	control := Object(storage.KindControl, "", "signed-control-1", "")
	request := Object(storage.KindRequest, "", "signed-request-1", "")
	for _, o := range []storage.Object{state, control, request} {
		if err := s.Publish(ctx, o); err != nil {
			t.Fatalf("publish %s: %v", o.Kind, err)
		}
		if err := s.Publish(ctx, o); err != nil {
			t.Fatalf("publish %s again must be idempotent: %v", o.Kind, err)
		}
		got, err := s.Fetch(ctx, o.Kind, o.Scope, o.Rev)
		if err != nil {
			t.Fatalf("fetch %s: %v", o.Kind, err)
		}
		if !bytes.Equal(got.Signed, o.Signed) || !bytes.Equal(got.Cipher, o.Cipher) || got.Rev != o.Rev {
			t.Fatalf("%s round trip changed the object", o.Kind)
		}
	}

	// A name holds one content. The same revision with other bytes is rejected.
	forged := state
	forged.Cipher = []byte("other ciphertext")
	if err := s.Publish(ctx, forged); err == nil || !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("republishing different content: %v", err)
	}

	// Discover is scoped by kind and scope.
	state2 := Object(storage.KindState, scope, "signed-state-2", "ciphertext-2")
	elsewhere := Object(storage.KindState, other, "signed-state-3", "ciphertext-3")
	for _, o := range []storage.Object{state2, elsewhere} {
		if err := s.Publish(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	revs, err := s.Discover(ctx, storage.KindState, scope)
	if err != nil {
		t.Fatal(err)
	}
	if want := sortedRevs(state.Rev, state2.Rev); !equalRevs(revs, want) {
		t.Fatalf("discover state = %v, want %v", revs, want)
	}
	if revs, err := s.Discover(ctx, storage.KindControl, ""); err != nil || !equalRevs(revs, []digest.Digest{control.Rev}) {
		t.Fatalf("discover control = %v %v", revs, err)
	}
	if revs, err := s.Discover(ctx, storage.KindState, Scope("secrets/none")); err != nil || len(revs) != 0 {
		t.Fatalf("discover empty scope = %v %v", revs, err)
	}

	// Missing and invalid references.
	if _, err := s.Fetch(ctx, storage.KindState, scope, digest.FromString("missing")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := s.Fetch(ctx, storage.KindState, "../escape", state.Rev); err == nil {
		t.Fatal("invalid scope accepted")
	}
	if _, err := s.Fetch(ctx, storage.KindControl, "", "sha256:xyz"); err == nil {
		t.Fatal("invalid digest accepted")
	}
	bad := state
	bad.Rev = digest.FromString("something else")
	if err := s.Publish(ctx, bad); err == nil {
		t.Fatal("object whose revision is not the digest of its bytes was published")
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
		if _, err := s.Fetch(ctx, storage.KindState, scope, state2.Rev); !errors.Is(err, storage.ErrNotFound) {
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

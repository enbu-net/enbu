// Package storagetest provides an in-memory Store, fault injection, and the
// contract every storage backend must satisfy.
package storagetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
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
		if bytes.Equal(old.Head, o.Head) && bytes.Equal(old.Payload, o.Payload) {
			return nil
		}
		return fmt.Errorf("%w: %s already holds different content", storage.ErrCorrupt, name)
	}
	o.Head, o.Payload = bytes.Clone(o.Head), bytes.Clone(o.Payload)
	m.objs[name] = o
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

func (m *Memory) OpenPayload(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o, err := m.get(kind, scope, rev)
	if err != nil {
		return nil, err
	}
	if len(o.Payload) == 0 {
		return nil, fmt.Errorf("%w: no payload", storage.ErrNotFound)
	}
	return io.NopCloser(bytes.NewReader(o.Payload)), nil
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
			if kind == storage.KindRequest && len(revs) > storage.MaxRequestRefs {
				return nil, storage.ErrDiscoveryLimit
			}
		}
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	return revs, nil
}

func (m *Memory) Scopes(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := map[string]bool{}
	var scopes []string
	for _, o := range m.objs {
		if o.Kind == storage.KindState && !seen[o.Scope] {
			seen[o.Scope] = true
			scopes = append(scopes, o.Scope)
		}
	}
	sort.Strings(scopes)
	return scopes, nil
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
	Publish     func(ctx context.Context, next storage.Store, o storage.Object) error
	FetchHead   func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) ([]byte, error)
	OpenPayload func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error)
	Discover    func(ctx context.Context, next storage.Store, kind storage.Kind, scope string) ([]digest.Digest, error)
	Delete      func(ctx context.Context, next storage.Store, kind storage.Kind, scope string, rev digest.Digest) error
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

func (w hooked) OpenPayload(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
	if w.h.OpenPayload != nil {
		return w.h.OpenPayload(ctx, w.Store, kind, scope, rev)
	}
	return w.Store.OpenPayload(ctx, kind, scope, rev)
}

func (w hooked) Discover(ctx context.Context, kind storage.Kind, scope string) ([]digest.Digest, error) {
	if w.h.Discover != nil {
		return w.h.Discover(ctx, w.Store, kind, scope)
	}
	return w.Store.Discover(ctx, kind, scope)
}

// CanDelete reports what the wrapped store reports.
func (w hooked) CanDelete() bool { return storage.CanDelete(w.Store) }

func (w hooked) Delete(ctx context.Context, kind storage.Kind, scope string, rev digest.Digest) error {
	if w.h.Delete != nil {
		return w.h.Delete(ctx, w.Store, kind, scope, rev)
	}
	return w.Store.Delete(ctx, kind, scope, rev)
}

// Object builds a valid object whose revision is the digest of head, with the
// given payload ("" for none).
func Object(kind storage.Kind, scope string, head, payload string) storage.Object {
	return storage.Object{Kind: kind, Scope: scope, Rev: digest.FromString(head), Head: []byte(head), Payload: []byte(payload)}
}

// Scope returns a valid state scope derived from name.
func Scope(name string) string { return storage.StateScope("workspace", name) }

// Contract checks the behavior every backend must provide.
func Contract(t *testing.T, s storage.Store) {
	t.Helper()
	ctx := context.Background()
	scope, other := Scope("secrets/dev"), Scope("secrets/prod")

	state := Object(storage.KindState, scope, "head-state-1", "ciphertext-1")
	control := Object(storage.KindControl, "", "head-control-1", "")
	request := Object(storage.KindRequest, "", "head-request-1", "")
	large := Object(storage.KindState, scope, "head-large", strings.Repeat("x", 100000))
	for _, o := range []storage.Object{state, control, request, large} {
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
		got, err := storage.ReadPayload(ctx, s, o.Kind, o.Scope, o.Rev, storage.MaxPayloadBytes)
		if len(o.Payload) == 0 {
			if !errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("a payload that is not there: %v", err)
			}
		} else if err != nil || !bytes.Equal(got, o.Payload) {
			t.Fatalf("payload of %s: %v", o.Kind, err)
		}
	}

	// A name holds one content. The same head with another payload is rejected.
	forged := state
	forged.Payload = []byte("other ciphertext")
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
	if want := sortedRevs(state.Rev, state2.Rev, large.Rev); !equalRevs(revs, want) {
		t.Fatalf("discover state = %v, want %v", revs, want)
	}
	if revs, err := s.Discover(ctx, storage.KindControl, ""); err != nil || !equalRevs(revs, []digest.Digest{control.Rev}) {
		t.Fatalf("discover control = %v %v", revs, err)
	}
	if revs, err := s.Discover(ctx, storage.KindState, Scope("secrets/none")); err != nil || len(revs) != 0 {
		t.Fatalf("discover empty scope = %v %v", revs, err)
	}
	// Scopes lists every state scope once, and nothing of other kinds.
	if scopes, err := s.Scopes(ctx); err != nil || !slices.Equal(scopes, sortedScopes(scope, other)) {
		t.Fatalf("scopes = %v %v, want %v", scopes, err, sortedScopes(scope, other))
	}

	// Missing and invalid references.
	if _, err := s.FetchHead(ctx, storage.KindState, scope, digest.FromString("missing")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := s.OpenPayload(ctx, storage.KindState, scope, digest.FromString("missing")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing payload: %v", err)
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

	// Delete removes the object, or reports that the backend cannot.
	err = s.Delete(ctx, storage.KindState, scope, state2.Rev)
	switch {
	case errors.Is(err, storage.ErrUnsupported):
		if _, err := s.FetchHead(ctx, storage.KindState, scope, state2.Rev); err != nil {
			t.Fatalf("fetch after an unsupported delete: %v", err)
		}
	case err != nil:
		t.Fatalf("delete: %v", err)
	default:
		if _, err := s.FetchHead(ctx, storage.KindState, scope, state2.Rev); !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("fetch after delete: %v", err)
		}
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Discover(cctx, storage.KindState, scope); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled discover: %v", err)
	}
}

func sortedScopes(scopes ...string) []string {
	out := slices.Clone(scopes)
	sort.Strings(out)
	return out
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

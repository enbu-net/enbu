package simulation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
	"io"
	"sync"
)

var ErrOffline = errors.New("simulated network partition")

// ErrCrash aborts application control flow at a recorded storage boundary. The
// harness catches only this sentinel and recreates the App from durable fixtures.
var ErrCrash = errors.New("simulated device crash")

func catchCrash(run func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if recovered == ErrCrash {
				err = ErrCrash
			} else {
				panic(recovered)
			}
		}
	}()
	return run()
}

// Fault targets an exact occurrence at an external boundary, rather than a
// wall-clock duration. After is meaningful for writes: durable effect, lost reply.
type Fault struct {
	Method string
	At     int
	Mode   string
}
type Store struct {
	mu      sync.Mutex
	advance func()
	storage.Store
	Actor     *Actor
	Tape      *Tape
	Device    int
	Fault     Fault
	calls     map[string]int
	ordinal   int
	faultHits int
	listings  map[string][]digest.Digest
	cancel    context.CancelFunc
}

func (s *Store) effect(method string, input any, f func(string) (any, error)) error {
	run := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.advance != nil {
			s.advance()
		}
		if s.calls == nil {
			s.calls = map[string]int{}
		}
		s.calls[method]++
		s.ordinal++
		occurrence := s.calls[method]
		if s.Fault.Method == "*" {
			occurrence = s.ordinal
		}
		mode := ""
		if (s.Fault.Method == method || s.Fault.Method == "*") && (s.Fault.At == 0 || s.Fault.At == occurrence) {
			mode = s.Fault.Mode
			s.faultHits++
		}
		in := struct {
			Device int
			Method string
			Input  any
			Mode   string
		}{s.Device, method, input, mode}
		if e := s.Tape.Observe("storage-request", nil, in); e != nil {
			return e
		}
		if mode == "context-before" || mode == "context-after" {
			if s.cancel == nil {
				return fmt.Errorf("context cancellation fault has no operation cancel function")
			}
			if mode == "context-before" {
				s.cancel()
			}
		}
		out, e := f(mode)
		if mode == "context-after" {
			s.cancel()
			if e == nil {
				e = context.Canceled
			}
		}
		code := ""
		switch {
		case e == nil:
		case errors.Is(e, ErrOffline):
			code = "offline"
		case errors.Is(e, storage.ErrNotFound):
			code = "not-found"
		case errors.Is(e, storage.ErrCorrupt):
			code = "corrupt"
		case errors.Is(e, context.Canceled):
			code = "canceled"
		case errors.Is(e, io.ErrUnexpectedEOF):
			code = "short-read"
		default:
			code = fmt.Sprintf("%T:%v", e, e)
		}
		if te := s.Tape.Observe("storage-response", nil, struct {
			Output any
			Error  string
		}{out, code}); te != nil {
			return te
		}
		return e
	}
	var err error
	if s.Actor != nil {
		err = s.Actor.Boundary(method, run)
	} else {
		err = run()
	}
	if errors.Is(err, ErrCrash) {
		panic(ErrCrash)
	}
	return err
}
func before(ctx context.Context, mode string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if mode == "crash-before" {
		return ErrCrash
	}
	if mode == "before" || mode == "partition" {
		return ErrOffline
	}
	if mode == "cancel" {
		return context.Canceled
	}
	return nil
}
func (s *Store) Publish(ctx context.Context, o storage.Object) error {
	return s.effect("publish", o, func(mode string) (any, error) {
		if e := before(ctx, mode); e != nil {
			return nil, e
		}
		e := s.Store.Publish(ctx, o)
		if e == nil && mode == "after" {
			e = ErrOffline
		}
		if e == nil && mode == "crash-after" {
			e = ErrCrash
		}
		return nil, e
	})
}
func (s *Store) FetchHead(ctx context.Context, k storage.Kind, scope string, r digest.Digest) (out []byte, err error) {
	err = s.effect("head", []any{k, scope, r}, func(mode string) (any, error) {
		if e := before(ctx, mode); e != nil {
			return nil, e
		}
		var e error
		out, e = s.Store.FetchHead(ctx, k, scope, r)
		if mode == "missing" {
			out = nil
			e = storage.ErrNotFound
		}
		if mode == "corrupt" && len(out) > 0 {
			out = bytes.Clone(out)
			out[0] ^= 1
		}
		return out, e
	})
	return
}
func (s *Store) OpenPayload(ctx context.Context, k storage.Kind, scope string, r digest.Digest) (io.ReadCloser, error) {
	var data []byte
	short := false
	e := s.effect("blob", []any{k, scope, r}, func(mode string) (any, error) {
		if e := before(ctx, mode); e != nil {
			return nil, e
		}
		rc, e := s.Store.OpenPayload(ctx, k, scope, r)
		if e != nil {
			return nil, e
		}
		data, e = io.ReadAll(rc)
		_ = rc.Close()
		if mode == "corrupt" && len(data) > 0 {
			data[0] ^= 1
		}
		if mode == "missing" {
			return nil, storage.ErrNotFound
		}
		short = mode == "short"
		return struct {
			Data  []byte
			Short bool
		}{data, short}, e
	})
	if e != nil {
		return nil, e
	}
	if short {
		return &brokenReader{data: data[:len(data)/2]}, nil
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type brokenReader struct{ data []byte }

func (r *brokenReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
func (*brokenReader) Close() error { return nil }
func (s *Store) Discover(ctx context.Context, k storage.Kind, scope string) (out []digest.Digest, err error) {
	err = s.effect("discover", []any{k, scope}, func(mode string) (any, error) {
		if e := before(ctx, mode); e != nil {
			return nil, e
		}
		var e error
		out, e = s.Store.Discover(ctx, k, scope)
		key := string(k) + scope
		if s.listings == nil {
			s.listings = map[string][]digest.Digest{}
		}
		if mode == "stale" {
			out = append([]digest.Digest(nil), s.listings[key]...)
		} else {
			s.listings[key] = append([]digest.Digest(nil), out...)
		}
		return out, e
	})
	return
}
func (s *Store) Scopes(ctx context.Context) (out []string, err error) {
	err = s.effect("scopes", nil, func(mode string) (any, error) {
		if e := before(ctx, mode); e != nil {
			return nil, e
		}
		var e error
		out, e = s.Store.Scopes(ctx)
		if mode == "stale" {
			out = nil
		}
		return out, e
	})
	return
}
func (s *Store) Delete(ctx context.Context, k storage.Kind, scope string, r digest.Digest) error {
	return s.effect("delete", []any{k, scope, r}, func(mode string) (any, error) {
		if e := before(ctx, mode); e != nil {
			return nil, e
		}
		e := s.Store.Delete(ctx, k, scope, r)
		if e == nil && mode == "after" {
			e = ErrOffline
		}
		if e == nil && mode == "crash-after" {
			e = ErrCrash
		}
		return nil, e
	})
}
func (s *Store) Arm(f Fault) { s.Fault = f; s.calls = map[string]int{}; s.ordinal = 0; s.faultHits = 0 }

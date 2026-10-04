package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
)

func putBlob(t *testing.T, s *Store, data string) digest.Digest {
	t.Helper()
	d, err := s.Blobs.Put(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func contract(t *testing.T, s *Store) {
	t.Helper()
	blobContract(t, s)
	refContract(t, s)
}

func blobContract(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	data := []byte{0, 1, 2, 255}
	d := putBlob(t, s, string(data))
	if d != digest.FromBytes(data) {
		t.Fatalf("digest=%s", d)
	}
	if again := putBlob(t, s, string(data)); again != d {
		t.Fatalf("second put=%s", again)
	}
	rc, err := s.Blobs.Open(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("open=%v %v", got, err)
	}
	if _, err := s.Blobs.Open(ctx, digest.FromString("missing")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	for _, bad := range []digest.Digest{"", "sha256:xyz", "sha512:" + digest.Digest(strings.Repeat("a", 128)), "../escape"} {
		if _, err := s.Blobs.Open(ctx, bad); err == nil {
			t.Fatalf("invalid digest %q accepted", bad)
		}
	}
	if _, err := s.Blobs.Put(ctx, bytes.NewReader(make([]byte, MaxPayloadBytes+1))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized payload: %v", err)
	}
	if _, err := s.Blobs.Put(ctx, strings.NewReader("")); !errors.Is(err, ErrEmptyBlob) {
		t.Fatalf("empty payload: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Blobs.Put(canceled, strings.NewReader("x")); err == nil {
		t.Fatal("canceled put succeeded")
	}
}

func refContract(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := s.Refs.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	a, b := putBlob(t, s, "a"), putBlob(t, s, "b")
	if err := s.Refs.Put(ctx, "secret", a, ""); err != nil {
		t.Fatal(err)
	}
	got, v, err := s.Refs.Get(ctx, "secret")
	if err != nil || got != a || v == "" {
		t.Fatalf("get=%s %q %v", got, v, err)
	}
	if err := s.Refs.Put(ctx, "secret", b, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("create existing: %v", err)
	}
	if err := s.Refs.Put(ctx, "secret", b, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	if err := s.Refs.Put(ctx, "secret", b, v); err != nil {
		t.Fatal(err)
	}
	got, v2, err := s.Refs.Get(ctx, "secret")
	if err != nil || got != b || v == v2 {
		t.Fatalf("update=%s %q %v", got, v2, err)
	}
	if err := s.Refs.Put(ctx, "secret-2", b, ""); err != nil {
		t.Fatal(err)
	}
	keys, err := s.Refs.List(ctx, "sec")
	if err != nil || !reflect.DeepEqual(keys, []string{"secret", "secret-2"}) {
		t.Fatalf("list=%v %v", keys, err)
	}
	keys, err = s.Refs.List(ctx, "none")
	if err != nil || len(keys) != 0 {
		t.Fatalf("empty list=%v %v", keys, err)
	}
	for _, key := range []string{"../escape", "a/b", ".", "..", "", "a:b"} {
		if err := s.Refs.Put(ctx, key, a, ""); err == nil {
			t.Fatalf("invalid key %q accepted", key)
		}
	}
	if err := s.Refs.Put(ctx, "bad-target", "sha256:xyz", ""); err == nil {
		t.Fatal("invalid target accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.Refs.Get(canceled, "secret"); err == nil {
		t.Fatal("canceled get succeeded")
	}
}

func atomicContract(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.Refs.Put(ctx, "race", putBlob(t, s, "base"), ""); err != nil {
		t.Fatal(err)
	}
	_, v, err := s.Refs.Get(ctx, "race")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		key     string
		version Version
	}{{"race", v}, {"create-race", ""}} {
		start := make(chan struct{})
		results := make(chan error, 16)
		for i := range 16 {
			target := putBlob(t, s, string([]byte{byte(i)}))
			go func() {
				<-start
				results <- s.Refs.Put(ctx, test.key, target, test.version)
			}()
		}
		close(start)
		success := 0
		for range 16 {
			err := <-results
			if err == nil {
				success++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatal(err)
			}
		}
		if success != 1 {
			t.Fatalf("%s: %d writers succeeded", test.key, success)
		}
	}
}

func TestLocalContract(t *testing.T) {
	dir := t.TempDir()
	s := NewLocal(dir)
	contract(t, s)
	atomicContract(t, s)
	for _, sub := range []string{".", "refs", "blobs/sha256"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".pending-") {
				t.Fatalf("temporary storage file was not removed: %s/%s", sub, entry.Name())
			}
		}
	}
}

func TestBlobDigestVerification(t *testing.T) {
	dir := t.TempDir()
	s := NewLocal(dir)
	d := putBlob(t, s, "secret")
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", d.Encoded()), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Blobs.Open(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered blob: %v", err)
	}
}

func TestLocalRejectsCorruptionAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	s := NewLocal(dir)
	ctx := context.Background()
	target := putBlob(t, s, "x")
	if err := os.MkdirAll(filepath.Join(dir, "refs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "refs", "bad"), []byte("not a digest"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Refs.Get(ctx, "bad"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corruption=%v", err)
	}
	if err := s.Refs.Put(ctx, "bad", target, ""); err == nil {
		t.Fatal("overwrote corruption")
	}
	if err := os.Symlink(filepath.Join(dir, "refs", "bad"), filepath.Join(dir, "refs", "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := s.Refs.Get(ctx, "link"); err == nil {
		t.Fatal("followed ref symlink")
	}
	blob := filepath.Join(dir, "blobs", "sha256", target.Encoded())
	if err := os.Remove(blob); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "refs", "bad"), blob); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Blobs.Open(ctx, target); err == nil {
		t.Fatal("followed blob symlink")
	}
}

func TestLocalLockCancellation(t *testing.T) {
	l := local{t.TempDir()}
	s := NewLocal(l.dir)
	ready := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = l.withLock(context.Background(), func(*os.Root) error { close(ready); <-release; return nil })
	})
	<-ready
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, _, err := s.Refs.Get(ctx, "key")
	close(release)
	wg.Wait()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock cancellation: %v", err)
	}
}

package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func contract(t *testing.T, s Storage) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := s.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	o := Object{MediaType: "application/test", Data: []byte{0, 1, 2, 255}}
	if err := s.Put(ctx, "secret", o, ""); err != nil {
		t.Fatal(err)
	}
	got, v, err := s.Get(ctx, "secret")
	if err != nil || !reflect.DeepEqual(got, o) || v == "" {
		t.Fatalf("get=%+v %q %v", got, v, err)
	}
	if err := s.Put(ctx, "secret", o, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("create existing: %v", err)
	}
	if err := s.Put(ctx, "secret", o, "stale"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	o.Data = []byte("new")
	if err := s.Put(ctx, "secret", o, v); err != nil {
		t.Fatal(err)
	}
	got, v2, err := s.Get(ctx, "secret")
	if err != nil || !reflect.DeepEqual(got, o) || v == v2 {
		t.Fatalf("update=%+v %q %v", got, v2, err)
	}
	keys, err := s.List(ctx, "sec")
	if err != nil || !reflect.DeepEqual(keys, []string{"secret"}) {
		t.Fatalf("list=%v %v", keys, err)
	}
	for _, key := range []string{"../escape", "a/b", ".", "..", "", "a:b"} {
		if err := s.Put(ctx, key, o, ""); err == nil {
			t.Fatalf("invalid key %q accepted", key)
		}
	}
	if err := s.Put(ctx, "large", Object{MediaType: o.MediaType, Data: make([]byte, MaxPayloadBytes+1)}, ""); err == nil {
		t.Fatal("oversized payload accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.Get(canceled, "secret"); err == nil {
		t.Fatal("canceled get succeeded")
	}
}

func atomicContract(t *testing.T, s Storage) {
	t.Helper()
	ctx := context.Background()
	o := Object{MediaType: "application/test", Data: []byte("base")}
	if err := s.Put(ctx, "race", o, ""); err != nil {
		t.Fatal(err)
	}
	_, v, err := s.Get(ctx, "race")
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
			go func() {
				<-start
				results <- s.Put(ctx, test.key, Object{MediaType: o.MediaType, Data: []byte{byte(i)}}, test.version)
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
	s := &Local{Dir: t.TempDir()}
	contract(t, s)
	atomicContract(t, s)
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != ".enbu.lock" && filepath.Ext(entry.Name()) != ".json" {
			t.Fatalf("temporary storage file was not removed: %s", entry.Name())
		}
	}
}

func TestEnvelopeCorruption(t *testing.T) {
	b, err := Encode(Object{MediaType: "application/test", Data: []byte("secret")})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte("{}"), bytes.Replace(b, []byte("sha256:"), []byte("sha257:"), 1), bytes.Replace(b, []byte("\"version\":1"), []byte("\"version\":2"), 1)} {
		if _, err := Decode(bad); err == nil {
			t.Fatalf("corrupt envelope accepted: %s", bad)
		}
	}
}

func TestLocalRejectsCorruptionAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	s := &Local{Dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(context.Background(), "bad"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corruption=%v", err)
	}
	if err := s.Put(context.Background(), "bad", Object{MediaType: "application/test"}, ""); err == nil {
		t.Fatal("overwrote corruption")
	}
	if err := os.Symlink(filepath.Join(dir, "bad.json"), filepath.Join(dir, "link.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := s.Get(context.Background(), "link"); err == nil {
		t.Fatal("followed symlink")
	}
}

func TestLocalLockCancellation(t *testing.T) {
	s := &Local{Dir: t.TempDir()}
	ready := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = s.withLock(context.Background(), func(*os.Root) error { close(ready); <-release; return nil })
	})
	<-ready
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, _, err := s.Get(ctx, "key")
	close(release)
	wg.Wait()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock cancellation: %v", err)
	}
}

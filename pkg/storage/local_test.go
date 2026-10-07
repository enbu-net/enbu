//go:build fixture

package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

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

func TestLocalBlobPutKeepsExistingFile(t *testing.T) {
	dir := t.TempDir()
	s := NewLocal(dir)
	d := putBlob(t, s, "same")
	path := filepath.Join(dir, "blobs", "sha256", d.Encoded())
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	putBlob(t, s, "same")
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("existing blob was replaced: %v", err)
	}
}

func TestLocalBlobPutRepairsDamagedBlob(t *testing.T) {
	dir := t.TempDir()
	s := NewLocal(dir)
	d := putBlob(t, s, "secret")
	path := filepath.Join(dir, "blobs", "sha256", d.Encoded())
	for _, damaged := range []string{"sec", "SECRET"} { // truncated, and same size with other content
		if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
			t.Fatal(err)
		}
		putBlob(t, s, "secret")
		rc, err := s.Blobs.Open(context.Background(), d)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || string(b) != "secret" {
			t.Fatalf("after repairing %q: blob=%q %v", damaged, b, err)
		}
	}
}

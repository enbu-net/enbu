package app

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileSecretCacheRoundTripAndPermissions(t *testing.T) {
	base := filepath.Join(t.TempDir(), "cache")
	cache := &fileSecretCache{baseDir: base}
	const ref = "ghcr.io/owner/repo-enbu:secrets-default"

	if _, err := cache.Load(ref); !errors.Is(err, ErrSecretCacheMiss) {
		t.Fatalf("Load before Store error = %v, want ErrSecretCacheMiss", err)
	}
	if err := cache.Store(ref, []byte("ciphertext")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	data, err := cache.Load(ref)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(data) != "ciphertext" {
		t.Fatalf("data = %q", data)
	}
	if err := cache.Store(ref, []byte("updated")); err != nil {
		t.Fatalf("Store overwrite: %v", err)
	}
	data, err = cache.Load(ref)
	if err != nil {
		t.Fatalf("Load after overwrite: %v", err)
	}
	if string(data) != "updated" {
		t.Fatalf("overwritten data = %q", data)
	}

	dirInfo, err := os.Stat(base)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(cache.path(ref))
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}

	if err := cache.Delete(ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cache.Load(ref); !errors.Is(err, ErrSecretCacheMiss) {
		t.Fatalf("Load after Delete error = %v, want ErrSecretCacheMiss", err)
	}
}

func TestFileSecretCacheSeparatesReferences(t *testing.T) {
	cache := &fileSecretCache{baseDir: t.TempDir()}
	first := "ghcr.io/owner/repo-enbu:secrets-dev"
	second := "ghcr.io/owner/repo-enbu:secrets-prod"

	if cache.path(first) == cache.path(second) {
		t.Fatal("different references resolved to the same cache path")
	}
}

func TestSecretCacheFallbackInitializationIsConcurrentSafe(t *testing.T) {
	a := &App{}
	caches := make([]SecretCache, 32)
	var wg sync.WaitGroup
	for i := range caches {
		wg.Add(1)
		go func() {
			defer wg.Done()
			caches[i] = a.secretCache()
		}()
	}
	wg.Wait()

	for i := 1; i < len(caches); i++ {
		if caches[i] != caches[0] {
			t.Fatal("concurrent calls returned different fallback caches")
		}
	}
}

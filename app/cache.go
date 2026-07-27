package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrSecretCacheMiss = errors.New("secret cache not found")

type fileSecretCache struct {
	baseDir string
}

func newFileSecretCache() SecretCache {
	base, err := os.UserCacheDir()
	if err != nil {
		return &unavailableSecretCache{err: fmt.Errorf("resolving user cache directory: %w", err)}
	}
	return &fileSecretCache{baseDir: filepath.Join(base, "enbu", "secrets")}
}

func (c *fileSecretCache) path(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return filepath.Join(c.baseDir, hex.EncodeToString(sum[:])+".age")
}

func (c *fileSecretCache) Load(ref string) ([]byte, error) {
	data, err := os.ReadFile(c.path(ref))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrSecretCacheMiss
		}
		return nil, fmt.Errorf("reading secret cache: %w", err)
	}
	return data, nil
}

func (c *fileSecretCache) Store(ref string, ciphertext []byte) error {
	if err := os.MkdirAll(c.baseDir, 0o700); err != nil {
		return fmt.Errorf("creating secret cache directory: %w", err)
	}
	if err := os.Chmod(c.baseDir, 0o700); err != nil {
		return fmt.Errorf("securing secret cache directory: %w", err)
	}

	tmp, err := os.CreateTemp(c.baseDir, ".secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temporary secret cache: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("securing temporary secret cache: %w", err)
	}
	if _, err := tmp.Write(ciphertext); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temporary secret cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing temporary secret cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temporary secret cache: %w", err)
	}
	if err := replaceFile(tmpPath, c.path(ref)); err != nil {
		return fmt.Errorf("replacing secret cache: %w", err)
	}
	return nil
}

func (c *fileSecretCache) Delete(ref string) error {
	if err := os.Remove(c.path(ref)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deleting secret cache: %w", err)
	}
	return nil
}

type unavailableSecretCache struct {
	err error
}

func (c *unavailableSecretCache) Load(string) ([]byte, error) {
	return nil, c.err
}

func (c *unavailableSecretCache) Store(string, []byte) error {
	return c.err
}

func (c *unavailableSecretCache) Delete(string) error {
	return c.err
}

func (a *App) secretCache() SecretCache {
	if a.SecretCache != nil {
		return a.SecretCache
	}
	a.fallbackOnce.Do(func() {
		a.fallbackCache = newMemorySecretCache()
	})
	return a.fallbackCache
}

type memorySecretCache struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMemorySecretCache() SecretCache {
	return &memorySecretCache{data: make(map[string][]byte)}
}

func (c *memorySecretCache) Load(ref string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, ok := c.data[ref]
	if !ok {
		return nil, ErrSecretCacheMiss
	}
	return append([]byte(nil), data...), nil
}

func (c *memorySecretCache) Store(ref string, ciphertext []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[ref] = append([]byte(nil), ciphertext...)
	return nil
}

func (c *memorySecretCache) Delete(ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, ref)
	return nil
}

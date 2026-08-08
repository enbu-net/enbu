// Package platform contains the small OS-neutral security boundary shared by
// the application host. It never handles plaintext secrets; it only creates
// private directories/files and process-local coordination primitives.
package platform

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	ErrUnsafePath    = errors.New("platform: unsafe path")
	ErrInsecureFile  = errors.New("platform: insecure file permissions")
	ErrAlreadyLocked = errors.New("platform: lock already held")
)

// DataDir returns the per-user application data directory without consulting
// an untrusted project directory or environment variable. XDG_DATA_HOME is
// honored on Unix; UserConfigDir covers macOS and Windows native locations.
func DataDir() (string, error) {
	if runtime.GOOS != "windows" {
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" && filepath.IsAbs(xdg) {
			return filepath.Join(xdg, "enbu"), nil
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("platform: user config dir: %w", err)
	}
	return filepath.Join(base, "enbu"), nil
}

func EnsurePrivateDir(path string) error {
	if err := validateAbsolute(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("platform: create private directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: private directory is not a real directory", ErrUnsafePath)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("%w: chmod directory: %v", ErrInsecureFile, err)
		}
	}
	return nil
}

// SecureWriter atomically creates a new private file. Existing files and
// symlink targets are rejected; callers must fsync before making the file
// visible in a higher-level index.
func SecureWriter(path string) (*os.File, error) {
	if err := validateAbsolute(path); err != nil {
		return nil, err
	}
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("platform: create secure file: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("%w: chmod file: %v", ErrInsecureFile, err)
		}
	}
	return file, nil
}

// Lock is process-local and intentionally does not pretend to coordinate
// remote clients. It protects local configuration and materialization only.
type Lock struct {
	mu sync.Mutex
}

func (lock *Lock) Acquire() func() {
	lock.mu.Lock()
	return lock.mu.Unlock
}

func ValidatePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrUnsafePath)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: mode %o", ErrInsecureFile, info.Mode().Perm())
	}
	return nil
}

func SyncAndClose(file *os.File) error {
	if file == nil {
		return errors.New("platform: nil file")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func validateAbsolute(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: path must be absolute and clean", ErrUnsafePath)
	}
	return nil
}

var _ io.Writer = (*os.File)(nil)

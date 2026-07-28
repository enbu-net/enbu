package keystore

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type TextBackend struct{}

func (t *TextBackend) Store(service, key string, secret []byte) error {
	path := filepath.Join(textBackendDir(), service+"_"+sanitizeKey(key))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating keystore directory: %w", err)
	}
	return os.WriteFile(path, secret, 0o600)
}

func (t *TextBackend) Load(service, key string) ([]byte, error) {
	path := filepath.Join(textBackendDir(), service+"_"+sanitizeKey(key))
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	return b, nil
}

func (t *TextBackend) Delete(service, key string) error {
	path := filepath.Join(textBackendDir(), service+"_"+sanitizeKey(key))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func sanitizeKey(key string) string {
	return strings.ReplaceAll(key, "/", "_")
}

func textBackendDir() string {
	if dir := os.Getenv("ENBU_TEXT_BACKEND_DIR"); dir != "" {
		return dir
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "enbu", "keys")
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "enbu", "keys")
	default:
		return filepath.Join(os.Getenv("HOME"), ".local", "share", "enbu", "keys")
	}
}

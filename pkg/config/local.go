package config

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/enbu-net/enbu/pkg/fsutil"
)

// LocalConfig is per-user state of one workspace, kept outside the repository.
type LocalConfig struct {
	Current  string `toml:"current,omitempty"`
	Previous string `toml:"previous,omitempty"`
}

// LocalStatePath returns the XDG data dir path for per-project local state.
func LocalStatePath(workspaceID string) string {
	return filepath.Join(DataDir(), "state", uuidOrHash(workspaceID)+".toml")
}

// LoadLocalStateFrom reads local state for one explicitly selected device.
func LoadLocalStateFrom(dir, workspaceID string) (*LocalConfig, error) {
	path := filepath.Join(dir, "state", uuidOrHash(workspaceID)+".toml")
	var cfg LocalConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		if os.IsNotExist(err) {
			return &LocalConfig{}, nil
		}
		return nil, fmt.Errorf("reading local state: %w", err)
	}
	return &cfg, nil
}

// SaveLocalStateTo persists local state for one explicitly selected device.
func SaveLocalStateTo(dir, workspaceID string, cfg *LocalConfig) error {
	path := filepath.Join(dir, "state", uuidOrHash(workspaceID)+".toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing state file: %w", err)
	}
	return nil
}

func uuidOrHash(id string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(id))) }

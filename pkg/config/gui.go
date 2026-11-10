package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/fsutil"

	"github.com/BurntSushi/toml"
)

type GUIConfig struct {
	SelectedRepo string   `toml:"selected_repo,omitempty"`
	RepoHistory  []string `toml:"repo_history,omitempty"`
}

func LoadGUI() (*GUIConfig, error) {
	path := guiConfigPath()
	var cfg GUIConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		if os.IsNotExist(err) {
			return &GUIConfig{}, nil
		}
		return nil, fmt.Errorf("parsing GUI config: %w", err)
	}
	return &cfg, nil
}

func SaveGUI(cfg *GUIConfig) error {
	dir := DataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return fmt.Errorf("encoding GUI config: %w", err)
	}

	if err := fsutil.WriteFileAtomic(guiConfigPath(), buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("writing GUI config: %w", err)
	}
	return nil
}

func guiConfigPath() string {
	return filepath.Join(DataDir(), "gui.toml")
}

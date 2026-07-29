package config

import (
	"fmt"
	"os"
	"path/filepath"

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
	if err := os.MkdirAll(DataDir(), 0o700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	f, err := os.OpenFile(guiConfigPath(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating GUI config: %w", err)
	}

	encoder := toml.NewEncoder(f)
	if err := encoder.Encode(cfg); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func guiConfigPath() string {
	return filepath.Join(DataDir(), "gui.toml")
}

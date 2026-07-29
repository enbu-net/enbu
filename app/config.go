package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
)

func (a *App) ReadConfig() (content string, err error) {
	defer apperr.NormalizeInto(&err)

	path, err := config.ProjectConfigPathFrom(a.RepositoryDir)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeConfigNotFound, "enbu.toml not found", err, nil)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", apperr.Wrap(apperr.CodeConfigNotFound, "enbu.toml not found", err, nil)
		}
		return "", fmt.Errorf("reading enbu.toml: %w", err)
	}
	return string(data), nil
}

func (a *App) WriteConfig(content string) (err error) {
	defer apperr.NormalizeInto(&err)

	cfg, err := config.ParseProject(content)
	if err != nil {
		return err
	}
	if err := config.ValidateProjectOutputs(cfg); err != nil {
		return err
	}
	path, err := config.ProjectConfigPathFrom(a.RepositoryDir)
	if err != nil {
		path = filepath.Join(a.RepositoryDir, "enbu.toml")
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

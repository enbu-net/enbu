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
	// Fail closed: a current file that cannot be read may hold values to protect.
	existing, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return fmt.Errorf("reading enbu.toml: %w", err)
	default:
		current, err := config.DecodeProject(string(existing))
		if err != nil {
			return apperr.Wrap(apperr.CodeInvalidArgument, "the current enbu.toml cannot be read, so this edit cannot be checked; fix it in a text editor", err, nil)
		}
		if err := checkProtectedConfig(current, cfg); err != nil {
			return err
		}
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// checkProtectedConfig refuses an edit of enbu.toml that changes what the
// workspace trusts or where an environment's secrets are stored. Changing the
// genesis would silently trust another member list, and changing where an
// environment is stored would show other (or no) secrets under its name. These
// change only through enbu's own commands; an editor that loses them by mistake
// must not break the workspace.
func checkProtectedConfig(current, next *config.ProjectConfig) error {
	protected := func(key string) error {
		return apperr.New(apperr.CodeConfigProtected, fmt.Sprintf("%s cannot be changed by editing enbu.toml here", key), apperr.Params{"key": key})
	}
	if current.WorkspaceID != "" && next.WorkspaceID != current.WorkspaceID {
		return protected("workspace_id")
	}
	if current.ControlGenesis != "" && next.ControlGenesis != current.ControlGenesis {
		return protected("control_genesis")
	}
	for name := range next.Environments {
		if current.HasEnvironment(name) && next.Resource(name) != current.Resource(name) {
			return protected("env." + name + ".incarnation")
		}
	}
	return nil
}

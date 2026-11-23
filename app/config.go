package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
	"github.com/enbu-net/enbu/pkg/provider/git"
)

func (a *App) projectPath() string {
	if path, err := config.ProjectConfigPathFrom(a.RepositoryDir); err == nil {
		return path
	}
	return filepath.Join(a.RepositoryDir, "enbu.toml")
}

func (a *App) lockProject(ctx context.Context) (*os.File, error) {
	dir, err := filepath.EvalSymlinks(filepath.Dir(a.projectPath()))
	if err != nil {
		return nil, fmt.Errorf("resolving project directory: %w", err)
	}
	repository, err := git.NewClient().Inspect(ctx, dir)
	if err != nil {
		return nil, err
	}
	if repository.MetadataDir != "" {
		// The per-worktree metadata directory is outside Git's cleanup scope.
		dir = repository.MetadataDir
	}
	return fsutil.LockFileContext(ctx, a.clock(), filepath.Join(dir, config.ProjectLockName))
}

func (a *App) ReadConfig() (content string, err error) {
	defer apperr.NormalizeInto(&err)

	data, err := os.ReadFile(a.projectPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", apperr.Wrap(apperr.CodeConfigNotFound, "enbu.toml not found", err, nil)
		}
		return "", fmt.Errorf("reading enbu.toml: %w", err)
	}
	return string(data), nil
}

func (a *App) WriteConfig(content, previous string) (err error) {
	defer apperr.NormalizeInto(&err)

	cfg, err := config.ParseProject(content)
	if err != nil {
		if apperr.Is(err, apperr.CodeConfigResourceCollision) {
			return err
		}
		return apperr.Wrap(apperr.CodeInvalidArgument, "invalid project configuration", err, nil)
	}
	lock, err := a.lockProject(context.Background())
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	path := a.projectPath()
	// Fail closed: a current file that cannot be read may hold values to protect.
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("reading enbu.toml: %w", err)
	}
	if string(existing) != previous {
		return apperr.New(apperr.CodeConfigChanged, "enbu.toml changed since it was opened; reload it before saving", nil)
	}
	if err == nil {
		current, err := config.DecodeProject(string(existing))
		if err != nil {
			return apperr.Wrap(apperr.CodeInvalidArgument, "the current enbu.toml cannot be read, so this edit cannot be checked; fix it in a text editor", err, nil)
		}
		if apperr.Is(config.ValidateProjectOutputs(current), apperr.CodeConfigResourceCollision) {
			if _, err := cfg.Environment(cfg.CurrentEnvironment()); err != nil {
				return err
			}
		}
		if err := checkProtectedConfig(current, cfg); err != nil {
			return err
		}
	}
	if err := config.WriteProjectFile(path, []byte(content)); err != nil {
		return err
	}
	// The saved config is valid on its own. An output file Git does not ignore
	// could still be committed, so a failed update is reported, not skipped.
	if err := a.ensureGitignore(cfg); err != nil {
		return fmt.Errorf("enbu.toml was saved, but updating .gitignore failed: %w", err)
	}
	return nil
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
	if current.ControlGenesis != "" && next.Storage != current.Storage {
		return protected("storage")
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

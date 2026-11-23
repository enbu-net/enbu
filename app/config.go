package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
)

func (a *App) projectPath() string {
	if path, err := config.ProjectConfigPathFrom(a.RepositoryDir); err == nil {
		return path
	}
	return filepath.Join(a.RepositoryDir, "enbu.toml")
}

func (a *App) lockProject(ctx context.Context) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(a.projectPath()))
	if err != nil {
		return nil, fmt.Errorf("resolving project directory: %w", err)
	}
	info, err := os.Lstat(a.projectPath())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("checking project configuration: %w", err)
	}
	if err == nil && !info.Mode().IsRegular() {
		return nil, apperr.New(apperr.CodeInvalidArgument, "enbu.toml must be a regular file to change it", nil)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	lockDir, err := openProjectLockDir(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = lockDir.Close() }()

	info, err = lockDir.Lstat("project.lock")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if info != nil && !info.Mode().IsRegular() {
		return nil, apperr.New(apperr.CodeInvalidArgument, "project lock must be a regular file", nil)
	}
	return fsutil.LockFileContext(ctx, a.clock(), lockDir, "project.lock")
}

func openProjectLockDir(root *os.Root) (*os.Root, error) {
	const ignoreName = ".gitignore"
	const ignoreRule = "*\n"
	name := config.ProjectLockDir
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		// Publish the directory with its ignore rule already in place.
		// A concurrent caller may have installed the same directory.
		temp, createErr := os.MkdirTemp(root.Name(), name+"-")
		if createErr != nil {
			return nil, createErr
		}
		defer func() { _ = os.RemoveAll(temp) }()
		if err := os.WriteFile(filepath.Join(temp, ignoreName), []byte(ignoreRule), 0o644); err != nil {
			return nil, err
		}
		renameErr := root.Rename(filepath.Base(temp), name)
		info, err = root.Lstat(name)
		if err != nil && renameErr != nil {
			return nil, renameErr
		}
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, apperr.New(apperr.CodeInvalidArgument, "project lock path must be a directory", nil)
	}
	lockDir, err := root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	info, err = lockDir.Lstat(ignoreName)
	if err == nil && info.Mode().IsRegular() && info.Size() == int64(len(ignoreRule)) {
		file, err := lockDir.Open(ignoreName)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(file, int64(len(ignoreRule)+1)))
			_ = file.Close()
			if readErr == nil && bytes.Equal(data, []byte(ignoreRule)) {
				return lockDir, nil
			}
		}
	}
	_ = lockDir.Close()
	return nil, apperr.New(apperr.CodeInvalidArgument, "project lock directory has an unexpected Git exclusion file", nil)
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
	// Protect the new outputs before enabling them. If Git exclusions cannot
	// be written, the previous configuration is still the comparison base.
	if err := a.ensureGitignore(cfg); err != nil {
		return fmt.Errorf("updating .gitignore: %w", err)
	}
	// Keep the added exclusions up to the next successful save even if
	// replacing enbu.toml fails.
	return config.WriteProjectFile(path, []byte(content))
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

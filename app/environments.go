package app

import (
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/config"
)

type EnvInfo struct {
	Name      string
	IsCurrent bool
}

func (a *App) ListEnvironments() ([]EnvInfo, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return nil, err
	}

	current := cfg.CurrentEnvironment()
	names := cfg.EnvironmentNames()

	envs := make([]EnvInfo, len(names))
	for i, name := range names {
		envs[i] = EnvInfo{
			Name:      name,
			IsCurrent: name == current,
		}
	}
	return envs, nil
}

func (a *App) CurrentEnvironment() (string, error) {
	cfg, err := a.loadProject()
	if err != nil {
		return "", err
	}
	return cfg.CurrentEnvironment(), nil
}

func (a *App) SwitchEnvironment(name string) error {
	cfg, err := a.loadProject()
	if err != nil {
		return err
	}

	if !cfg.HasEnvironment(name) {
		return fmt.Errorf("environment %q does not exist (use create to add it)", name)
	}

	previous := cfg.CurrentEnvironment()
	if previous == name {
		return nil
	}

	cfg.SetDefault(name)

	if err := a.saveProject(cfg); err != nil {
		return err
	}

	if local, err := a.loadLocal(); err == nil && local != nil {
		local.Previous = previous
		_ = a.saveLocal(local)
	}

	return nil
}

func (a *App) SwitchPrevious() (string, error) {
	local, err := a.loadLocal()
	if err != nil || local.Previous == "" {
		return "", fmt.Errorf("no previous environment")
	}

	if err := a.SwitchEnvironment(local.Previous); err != nil {
		return "", err
	}
	return local.Previous, nil
}

func (a *App) CreateEnvironment(name string) error {
	if !config.ValidEnvironmentName(name) {
		return fmt.Errorf("invalid environment name %q", name)
	}

	cfg, err := a.loadProject()
	if err != nil {
		var notFound config.ErrConfigNotFound
		if !errors.As(err, &notFound) {
			return err
		}
		cfg = config.NewProjectWithEnvironment(name)
		if err := a.saveProject(cfg); err != nil {
			return err
		}
		return nil
	}

	if err := cfg.AddEnvironment(name); err != nil {
		return err
	}

	previous := cfg.CurrentEnvironment()
	cfg.SetDefault(name)

	if err := a.saveProject(cfg); err != nil {
		return err
	}

	if local, err := a.loadLocal(); err == nil && local != nil {
		local.Previous = previous
		_ = a.saveLocal(local)
	}

	return nil
}

func (a *App) DeleteEnvironment(name string) error {
	cfg, err := a.loadProject()
	if err != nil {
		return err
	}

	if cfg.CurrentEnvironment() == name {
		return fmt.Errorf("cannot delete the current environment '%s' (switch to another first)", name)
	}

	if err := cfg.RemoveEnvironment(name); err != nil {
		return err
	}

	if err := a.saveProject(cfg); err != nil {
		return err
	}
	if a.RepoDetector != nil {
		owner, repo, err := a.RepoDetector.LoadRepo()
		if err != nil {
			a.emit(fmt.Sprintf("Warning: environment was deleted, but its local secret cache could not be removed: %v", err))
			return nil
		}
		ref := a.secretsRef(owner, repo, name)
		if err := a.secretCache().Delete(ref); err != nil {
			a.emit(fmt.Sprintf("Warning: environment was deleted, but its local secret cache could not be removed: %v", err))
		}
	}
	return nil
}

func (a *App) RenameEnvironment(oldName, newName string) error {
	cfg, err := a.loadProject()
	if err != nil {
		return err
	}

	if err := cfg.RenameEnvironment(oldName, newName); err != nil {
		return err
	}

	if err := a.saveProject(cfg); err != nil {
		return err
	}
	if a.RepoDetector != nil {
		owner, repo, err := a.RepoDetector.LoadRepo()
		if err != nil {
			a.emit(fmt.Sprintf("Warning: environment was renamed, but its old local secret cache could not be removed: %v", err))
			return nil
		}
		ref := a.secretsRef(owner, repo, oldName)
		if err := a.secretCache().Delete(ref); err != nil {
			a.emit(fmt.Sprintf("Warning: environment was renamed, but its old local secret cache could not be removed: %v", err))
		}
	}
	return nil
}

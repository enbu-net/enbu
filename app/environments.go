package app

import (
	"fmt"

	"github.com/enbu-net/enbu/apperr"
	"github.com/enbu-net/enbu/config"
)

type EnvInfo struct {
	Name      string `json:"name"`
	IsCurrent bool   `json:"current"`
}

func (a *App) ListEnvironments() (envs []EnvInfo, err error) {
	defer apperr.NormalizeInto(&err)

	cfg, err := a.loadProject()
	if err != nil {
		return nil, err
	}

	current := cfg.CurrentEnvironment()
	names := cfg.EnvironmentNames()

	envs = make([]EnvInfo, len(names))
	for i, name := range names {
		envs[i] = EnvInfo{
			Name:      name,
			IsCurrent: name == current,
		}
	}
	return envs, nil
}

func (a *App) CurrentEnvironment() (name string, err error) {
	defer apperr.NormalizeInto(&err)

	cfg, err := a.loadProject()
	if err != nil {
		return "", err
	}
	return cfg.CurrentEnvironment(), nil
}

func (a *App) SwitchEnvironment(name string) (err error) {
	defer apperr.NormalizeInto(&err)

	if !config.ValidEnvironmentName(name) {
		return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("invalid environment name %q", name), apperr.Params{"name": name})
	}

	cfg, err := a.loadProject()
	if err != nil {
		return err
	}

	if !cfg.HasEnvironment(name) {
		return apperr.New(apperr.CodeEnvironmentMissing, fmt.Sprintf("environment %q does not exist (use create to add it)", name), apperr.Params{"name": name})
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

func (a *App) SwitchPrevious() (name string, err error) {
	defer apperr.NormalizeInto(&err)

	local, err := a.loadLocal()
	if err != nil || local.Previous == "" {
		return "", fmt.Errorf("no previous environment")
	}

	if err := a.SwitchEnvironment(local.Previous); err != nil {
		return "", err
	}
	return local.Previous, nil
}

func (a *App) CreateEnvironment(name string) (err error) {
	defer apperr.NormalizeInto(&err)

	if !config.ValidEnvironmentName(name) {
		return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("invalid environment name %q", name), apperr.Params{"name": name})
	}

	cfg, err := a.loadProject()
	if err != nil {
		if !apperr.Is(err, apperr.CodeConfigNotFound) {
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

func (a *App) DeleteEnvironment(name string) (err error) {
	defer apperr.NormalizeInto(&err)

	cfg, err := a.loadProject()
	if err != nil {
		return err
	}

	if cfg.CurrentEnvironment() == name {
		return apperr.New(
			apperr.CodeInvalidArgument,
			fmt.Sprintf("cannot delete the current environment %q (switch to another first)", name),
			apperr.Params{"name": name},
		)
	}

	if err := cfg.RemoveEnvironment(name); err != nil {
		return err
	}

	return a.saveProject(cfg)
}

func (a *App) RenameEnvironment(oldName, newName string) (err error) {
	defer apperr.NormalizeInto(&err)

	cfg, err := a.loadProject()
	if err != nil {
		return err
	}

	if err := cfg.RenameEnvironment(oldName, newName); err != nil {
		return err
	}

	return a.saveProject(cfg)
}

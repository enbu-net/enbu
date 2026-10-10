package app

import (
	"context"
	"fmt"
	"uuid"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
)

type EnvInfo struct {
	Name      string `json:"name"`
	IsCurrent bool   `json:"current"`
	// Incarnation names the environment's stored revisions. Keep it if the
	// environment is deleted without --purge: it is how they are found later.
	Incarnation string `json:"incarnation,omitempty"`
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
			Name:        name,
			IsCurrent:   name == current,
			Incarnation: cfg.Environments[name].Incarnation,
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
	if err := checkDeletable(cfg, name); err != nil {
		return err
	}
	if err := cfg.RemoveEnvironment(name); err != nil {
		return err
	}

	return a.saveProject(cfg)
}

// checkDeletable is everything that can make deleting an environment fail, so
// a caller can find out before it does anything it cannot take back.
func checkDeletable(cfg *config.ProjectConfig, name string) error {
	if cfg.CurrentEnvironment() == name {
		return apperr.New(
			apperr.CodeInvalidArgument,
			fmt.Sprintf("cannot delete the current environment %q (switch to another first)", name),
			apperr.Params{"name": name},
		)
	}
	if !cfg.HasEnvironment(name) {
		return apperr.New(apperr.CodeEnvironmentMissing, fmt.Sprintf("environment %q does not exist", name), apperr.Params{"name": name})
	}
	return nil
}

// DeleteEnvironmentPurging deletes an environment and its stored revisions.
// Every check runs first, so a deletion that would be refused never deletes
// secrets: the revisions go only when the environment can really be removed,
// and the environment stays in enbu.toml until they are gone so a failure
// halfway can simply be repeated.
func (a *App) DeleteEnvironmentPurging(ctx context.Context, name string) (purged int, err error) {
	defer apperr.NormalizeInto(&err)

	cfg, err := a.loadProject()
	if err != nil {
		return 0, err
	}
	if err := checkDeletable(cfg, name); err != nil {
		return 0, err
	}
	s, err := a.openPurgeSession(ctx)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if purged, err = s.purgeResource(ctx, cfg.Resource(name)); err != nil {
		return purged, err
	}
	if err := cfg.RemoveEnvironment(name); err != nil {
		return purged, err
	}
	return purged, a.saveProject(cfg)
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

// PurgeEnvironment deletes every stored revision of an environment that is
// still in enbu.toml and leaves the environment itself. It is how storage is
// reclaimed: enbu never trims history by itself. To delete the environment as
// well, use DeleteEnvironmentPurging. It returns how many revisions were deleted.
func (a *App) PurgeEnvironment(ctx context.Context, name string) (deleted int, err error) {
	defer apperr.NormalizeInto(&err)
	if _, err := a.resolveEnvironment(name); err != nil {
		return 0, err
	}
	cfg, err := a.loadProject()
	if err != nil {
		return 0, err
	}
	s, err := a.openPurgeSession(ctx)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	return s.purgeResource(ctx, cfg.Resource(name))
}

// PurgeIncarnation deletes the stored revisions of an environment that was
// deleted without --purge, which only forgot where they are. The incarnation is
// the one switch --delete printed (it is also in enbu.toml's git history). An
// incarnation that a current environment still uses is refused.
func (a *App) PurgeIncarnation(ctx context.Context, incarnation string) (deleted int, err error) {
	defer apperr.NormalizeInto(&err)
	if _, perr := uuid.Parse(incarnation); perr != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument, "an incarnation is a UUID", nil)
	}
	cfg, err := a.loadProject()
	if err != nil {
		return 0, err
	}
	for name, env := range cfg.Environments {
		if env.Incarnation == incarnation {
			return 0, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("environment %q still uses this incarnation; delete it with --purge instead", name), apperr.Params{"name": name})
		}
	}
	s, err := a.openPurgeSession(ctx)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	return s.purgeResource(ctx, "secrets/"+incarnation)
}

// openPurgeSession opens a session and checks that this device may delete and
// that the backend can, before anything is deleted. Deleting is not a right
// that writing to storage gives.
func (a *App) openPurgeSession(ctx context.Context) (*session, error) {
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, err
	}
	if p, _ := s.head.Principal(s.self()); !p.Admin {
		s.Close()
		return nil, apperr.New(apperr.CodeAccessDenied, "only a workspace admin can delete stored revisions", nil)
	}
	if !s.store.Capabilities().PhysicalDelete {
		s.Close()
		return nil, apperr.New(apperr.CodeInvalidArgument, "this storage cannot delete stored revisions", nil)
	}
	return s, nil
}

func (s *session) purgeResource(ctx context.Context, resource string) (deleted int, err error) {
	scope := storage.StateScope(s.workspace, resource)
	revs, err := s.store.Discover(ctx, storage.KindState, scope)
	if err != nil {
		return 0, storageError(err)
	}
	for _, rev := range revs {
		if err := s.store.Delete(ctx, storage.KindState, scope, rev); err != nil && !errorsIsNotFound(err) {
			return deleted, fmt.Errorf("deleting revision %s after %d deleted: %w", rev.Encoded(), deleted, storageError(err))
		}
		deleted++
	}
	return deleted, nil
}

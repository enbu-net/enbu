package app

import (
	"context"
	"fmt"

	"github.com/enbu-net/enbu/pkg/apperr"
)

var errNoChange = fmt.Errorf("secret unchanged")

// WorkspaceSnapshot combines the current environment and its content from
// the same verified session and project configuration.
type WorkspaceSnapshot struct {
	WorkspaceID  string
	Environments []EnvInfo
	Environment  string
	Secrets      map[string]string
	Conflicts    *ConflictSet
}

func (a *App) ReadWorkspace(ctx context.Context) (snapshot WorkspaceSnapshot, err error) {
	defer apperr.NormalizeInto(&err)
	s, err := a.openSession(ctx)
	if err != nil {
		return WorkspaceSnapshot{}, err
	}
	defer s.Close()
	env := s.cfg.CurrentEnvironment()
	if !s.cfg.HasEnvironment(env) {
		// The dashboard must still offer the remaining environments when its
		// configured selection is stale.
		env = s.cfg.EnvironmentNames()[0]
	}
	snapshot = WorkspaceSnapshot{
		WorkspaceID: s.workspace, Environments: environmentInfos(s.cfg, env), Environment: env,
	}
	read, err := s.readResource(ctx, s.resource(env), nil, true)
	if IsNotFoundError(err) {
		return snapshot, nil
	}
	if err != nil {
		return WorkspaceSnapshot{}, err
	}
	if len(read.conflicts) != 0 {
		snapshot.Conflicts = read.conflictSet(env)
	} else {
		snapshot.Secrets = read.secrets
	}
	return snapshot, nil
}

func (a *App) ListSecrets(ctx context.Context, env string) (result map[string]string, err error) {
	defer apperr.NormalizeInto(&err)
	s, resolved, err := a.openEnvironment(ctx, env)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	read, err := s.readResource(ctx, s.resource(resolved.Name), nil, true)
	if IsNotFoundError(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := conflictError(read.conflicts); err != nil {
		return nil, err
	}
	return read.secrets, nil
}

func (a *App) AddSecret(ctx context.Context, env, key, value string) (err error) {
	defer apperr.NormalizeInto(&err)
	return a.changeSecret(ctx, env, "add", func(secrets map[string]string) error {
		if _, ok := secrets[key]; ok {
			return apperr.New(apperr.CodeSecretExists, fmt.Sprintf("secret %s already exists", key), apperr.Params{"key": key})
		}
		secrets[key] = value
		return nil
	})
}
func (a *App) EditSecret(ctx context.Context, env, key, value string) (err error) {
	defer apperr.NormalizeInto(&err)
	return a.changeSecret(ctx, env, "edit", func(secrets map[string]string) error {
		if _, ok := secrets[key]; !ok {
			return apperr.New(apperr.CodeSecretMissing, fmt.Sprintf("secret %s does not exist", key), apperr.Params{"key": key})
		}
		secrets[key] = value
		return nil
	})
}
func (a *App) DeleteSecret(ctx context.Context, env, key string) (err error) {
	defer apperr.NormalizeInto(&err)
	return a.changeSecret(ctx, env, "delete", func(secrets map[string]string) error {
		if _, ok := secrets[key]; !ok {
			return errNoChange
		}
		delete(secrets, key)
		return nil
	})
}
func (a *App) SyncSecrets(ctx context.Context, env string) (err error) {
	defer apperr.NormalizeInto(&err)
	return a.changeSecret(ctx, env, "sync", func(map[string]string) error { return nil })
}

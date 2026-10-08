package app

import (
	"errors"
	"fmt"
	"io/fs"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/storage"
)

const (
	KeystoreService    = "enbu"
	DefaultEnvironment = "default"
)

func LoadIdentities(store IdentityStore, workspaceID string) ([]agecrypto.Identity, error) {
	if store == nil {
		return nil, fmt.Errorf("identity store is not initialized")
	}
	id, err := store.Load(workspaceID)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, apperr.New(apperr.CodeNotInitialized, "no identity found (run 'enbu init' first)", nil)
		}
		return nil, fmt.Errorf("loading identity: %w", err)
	}
	return []agecrypto.Identity{id}, nil
}

// CloseIdentities releases native references, TPM objects, sessions and devices.
func CloseIdentities(ids []agecrypto.Identity) {
	for _, id := range ids {
		if c, ok := id.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
}

func decryptSecretsObject(ciphertext []byte, identities ...agecrypto.Identity) (map[string]string, error) {
	plaintext, err := age.Decrypt(ciphertext, identities...)
	if err != nil {
		return nil, err
	}
	return bundle.Unmarshal(plaintext)
}

func IsNotFoundError(err error) bool {
	return apperr.Is(err, apperr.CodeArtifactNotFound)
}

type ResolvedEnvironment struct {
	Name   string
	Output string
}

func ResolveEnvironment(name string) (*ResolvedEnvironment, error) {
	return resolveEnvironment(config.LoadProject, name)
}

func (a *App) resolveEnvironment(name string) (*ResolvedEnvironment, error) {
	return resolveEnvironment(a.loadProject, name)
}

func resolveEnvironment(load func() (*config.ProjectConfig, error), name string) (*ResolvedEnvironment, error) {
	cfg, err := load()
	if err != nil {
		if apperr.Is(err, apperr.CodeConfigNotFound) {
			if name == "" {
				name = DefaultEnvironment
			}
			return &ResolvedEnvironment{
				Name:   name,
				Output: config.DefaultOutput(name),
			}, nil
		}
		return nil, err
	}

	if name == "" {
		name = cfg.CurrentEnvironment()
	}

	if !config.ValidEnvironmentName(name) {
		return nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("invalid environment %q", name), apperr.Params{"name": name})
	}

	env, err := cfg.Environment(name)
	if err != nil {
		return nil, err
	}
	return &ResolvedEnvironment{
		Name:   name,
		Output: env.Output,
	}, nil
}

func IsNotInitializedError(err error) bool {
	return apperr.Is(err, apperr.CodeConfigNotFound) ||
		apperr.Is(err, apperr.CodeNotInitialized)
}

func errorsIsNotFound(err error) bool { return errors.Is(err, storage.ErrNotFound) }

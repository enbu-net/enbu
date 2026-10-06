package app

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"
	"uuid"

	"crypto/sha256"
	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/config"
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

const workspaceKey = "enbu-workspace"

func decryptSecretsObject(ciphertext []byte, identities ...agecrypto.Identity) (map[string]string, error) {
	plaintext, err := age.Decrypt(ciphertext, identities...)
	if err != nil {
		return nil, err
	}
	return bundle.Unmarshal(plaintext)
}

func secretsTag(env string) string {
	if env == "" {
		env = DefaultEnvironment
	}
	return "secrets-" + env
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

func snapshotPrefix(env string) string {
	if env == "" {
		env = DefaultEnvironment
	}
	return fmt.Sprintf("hist-%x-", sha256.Sum256([]byte(env)))
}

func snapshotTag(env string) string {
	return fmt.Sprintf("%s%d-%s", snapshotPrefix(env), time.Now().UnixNano(), uuid.NewV4().String())
}

func IsSnapshotTag(env, tag string) bool { _, ok := snapshotTimestamp(env, tag); return ok }

func snapshotTimestamp(env, tag string) (time.Time, bool) {
	prefix := snapshotPrefix(env)
	if !strings.HasPrefix(tag, prefix) {
		return time.Time{}, false
	}
	tsText, id, ok := strings.Cut(strings.TrimPrefix(tag, prefix), "-")
	if !ok {
		return time.Time{}, false
	}
	if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
		return time.Time{}, false
	}
	ts, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil || ts < 0 {
		return time.Time{}, false
	}
	return time.Unix(0, ts), true
}

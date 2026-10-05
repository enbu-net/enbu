package app

import (
	"bytes"
	"context"
	"errors"
	agecrypto "filippo.io/age"
	"fmt"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/opencontainers/go-digest"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"
)

const maxRetries = 3

var errNoChange = fmt.Errorf("secret unchanged")

func (a *App) secretContext(ctx context.Context) (*storage.Store, []agecrypto.Identity, error) {
	store, err := a.workspaceStorage(ctx)
	if err != nil {
		return nil, nil, err
	}
	id, err := a.WorkspaceID()
	if err != nil {
		return nil, nil, err
	}
	ids, err := LoadIdentities(a.Identities, id)
	return store, ids, err
}

func (a *App) ListSecrets(ctx context.Context, env string) (result map[string]string, err error) {
	defer apperr.NormalizeInto(&err)
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	store, ids, err := a.secretContext(ctx)
	if err != nil {
		return nil, err
	}
	defer CloseIdentities(ids)
	secrets, _, err := PullSecretsWithVersion(ctx, store, secretsTag(resolved.Name), ids...)
	if IsNotFoundError(err) {
		return map[string]string{}, nil
	}
	return secrets, err
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

func (a *App) changeSecret(ctx context.Context, env, op string, change func(map[string]string) error) error {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return err
	}
	store, ids, err := a.secretContext(ctx)
	if err != nil {
		return err
	}
	defer CloseIdentities(ids)
	attempts := maxRetries
	if op == "sync" {
		attempts = 5
	}
	for attempt := 0; attempt < attempts; attempt++ {
		a.emitStepProgress(op, "pull_secrets", "start")
		secrets, version, err := PullSecretsWithVersion(ctx, store, secretsTag(resolved.Name), ids...)
		if err != nil {
			if !IsNotFoundError(err) {
				return fmt.Errorf("pulling secrets: %w", err)
			}
			if op == "sync" || op == "delete" {
				a.emitStepProgress(op, "pull_secrets", "done")
				return nil
			}
			if op == "edit" {
				return err
			}
			secrets = map[string]string{}
		}
		if err := change(secrets); err != nil {
			if err == errNoChange {
				a.emitStepProgress(op, "pull_secrets", "done")
				return nil
			}
			return err
		}
		a.emitStepProgress(op, "pull_recipients", "start")
		publicKeys, err := PullAllRecipients(ctx, store)
		if err != nil {
			return err
		}
		if len(publicKeys) == 0 {
			return fmt.Errorf("no recipients found")
		}
		a.emitStepProgress(op, "encrypt", "start")
		ciphertext, err := age.EncryptForPublicKeys(bundle.Marshal(secrets), publicKeys)
		if err != nil {
			return err
		}
		a.emitStepProgress(op, "push", "start")
		blob, err := store.Blobs.Put(ctx, bytes.NewReader(ciphertext))
		if err != nil {
			return fmt.Errorf("saving encrypted secrets: %w", storageError(err))
		}
		err = storageError(store.Refs.Put(ctx, secretsTag(resolved.Name), blob, version))
		if errors.Is(err, storage.ErrNotFound) {
			// The blob vanished between Blobs.Put and the ref update (registry GC).
			// Re-run the whole attempt, which uploads it again.
			if attempt == attempts-1 {
				return fmt.Errorf("saving encrypted secrets: uploaded blob disappeared before it was referenced: %v", err)
			}
			continue
		}
		if apperr.Is(err, apperr.CodeConflict) {
			if attempt == attempts-1 {
				return conflictRetriesExhausted(err, attempts)
			}
			a.emitRetry(attempt+1, attempts)
			delay := time.Duration(100+rand.IntN(100)) * time.Millisecond
			if op == "sync" {
				delay = time.Second * time.Duration(1<<attempt)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("saving encrypted secrets: %w", err)
		}
		if op != "sync" {
			a.saveSnapshot(ctx, store, resolved.Name, blob)
		}
		a.emitStepProgress(op, "push", "done")
		return nil
	}
	return nil
}

// saveSnapshot records a history entry as another ref to the secrets blob.
func (a *App) saveSnapshot(ctx context.Context, store *storage.Store, env string, blob digest.Digest) {
	if err := store.Refs.Put(ctx, snapshotTag(env), blob, ""); err != nil {
		a.emit(fmt.Sprintf("Secrets saved, but history snapshot failed: %v", err))
	}
}
func conflictRetriesExhausted(err error, attempts int) error {
	return fmt.Errorf("secrets changed by another user, failed after %d attempts: %w", attempts, err)
}

type PulledSecrets struct {
	Environment string
	Output      string
	Secrets     map[string]string
}

func (a *App) PullSecretsData(ctx context.Context, env string) (result *PulledSecrets, err error) {
	defer apperr.NormalizeInto(&err)

	return a.pullSecretsData(ctx, env, true)
}

func (a *App) PullSecrets(ctx context.Context, env string) (data []byte, output string, count int, err error) {
	defer apperr.NormalizeInto(&err)

	result, err := a.pullSecretsData(ctx, env, true)
	if err != nil {
		return nil, "", 0, err
	}
	dotenv, err := bundle.ToDotEnv(result.Secrets)
	if err != nil {
		return nil, "", 0, err
	}
	return dotenv, result.Output, len(result.Secrets), nil
}

func (a *App) pullSecretsData(ctx context.Context, env string, emitDone bool) (*PulledSecrets, error) {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	store, ids, err := a.secretContext(ctx)
	if err != nil {
		return nil, err
	}
	defer CloseIdentities(ids)
	a.emitStepProgress("pull", "pull_secrets", "start")
	a.emitStepProgress("pull", "decrypt", "start")
	secrets, _, err := PullSecretsWithVersion(ctx, store, secretsTag(resolved.Name), ids...)
	if err != nil {
		return nil, fmt.Errorf("pulling secrets: %w", err)
	}
	if emitDone {
		a.emitStepProgress("pull", "decrypt", "done")
	}
	return &PulledSecrets{Environment: resolved.Name, Output: resolved.Output, Secrets: secrets}, nil
}

func (a *App) PullSecretsToFile(ctx context.Context, env string) (err error) {
	defer apperr.NormalizeInto(&err)

	result, err := a.pullSecretsData(ctx, env, false)
	if err != nil {
		return err
	}

	outputPath := result.Output
	if a.RepositoryDir != "" && !filepath.IsAbs(result.Output) {
		outputPath = filepath.Join(a.RepositoryDir, result.Output)
	}
	a.emitStepProgress("pull", "write", "start")
	dotenv, err := bundle.ToDotEnv(result.Secrets)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, dotenv, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", result.Output, err)
	}

	a.emitStepProgress("pull", "write", "done")
	a.emit(fmt.Sprintf("Written %s (%d secrets)", result.Output, len(result.Secrets)))
	return nil
}

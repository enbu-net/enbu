package app

import (
	"context"
	"errors"
	agecrypto "filippo.io/age"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/bundle"
	"github.com/enbu-net/enbu/utils/oci"
)

const maxRetries = 3

func (a *App) ListSecrets(ctx context.Context, env string) (map[string]string, error) {
	secrets, _, err := a.ListSecretsWithCacheState(ctx, env)
	return secrets, err
}

func (a *App) ListSecretsWithCacheState(ctx context.Context, env string) (map[string]string, bool, error) {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, false, err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return nil, false, err
	}

	secretsRef := a.secretsRef(owner, repo, resolved.Name)
	ciphertext, err := a.secretCache().Load(secretsRef)
	if err != nil {
		if errors.Is(err, ErrSecretCacheMiss) {
			return map[string]string{}, false, nil
		}
		return nil, false, err
	}
	if len(ciphertext) == 0 {
		return map[string]string{}, true, nil
	}

	identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
	if err != nil {
		return nil, true, err
	}
	if len(identities) == 0 {
		return nil, true, fmt.Errorf("no decryption keys found (run 'enbu init' first)")
	}

	secrets, err := decryptSecretBundle(ciphertext, identities...)
	if err != nil {
		return nil, true, fmt.Errorf("reading cached secrets: %w", err)
	}

	return secrets, true, nil
}

func (a *App) AddSecret(ctx context.Context, env, key, value string) error {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return err
	}

	accessToken, _, err := a.TokenProvider.LoadToken()
	if err != nil {
		return err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return err
	}

	identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		return fmt.Errorf("no decryption keys found (run 'enbu init' first)")
	}

	secretsRef := a.secretsRef(owner, repo, resolved.Name)
	recipientsRef := a.registryRef(owner, repo)

	a.emitStepProgress("add", "pull_recipients", "start")
	publicKeys, err := PullAllRecipients(ctx, a.Registry, recipientsRef, accessToken)
	if err != nil {
		return fmt.Errorf("pulling recipients: %w", err)
	}
	if len(publicKeys) == 0 {
		return fmt.Errorf("no recipients found (has anyone run 'enbu init'?)")
	}

	pushOpts := &oci.PushOptions{
		SourceRepo: a.sourceRepoURL(owner, repo),
	}

	for attempt := range maxRetries {
		a.emitStepProgress("add", "pull_secrets", "start")
		secrets, baseDigest, err := PullSecretsWithDigest(ctx, a.Registry, secretsRef, accessToken, identities...)
		if err != nil {
			if !IsNotFoundError(err) {
				return fmt.Errorf("pulling secrets: %w", err)
			}
			secrets = make(map[string]string)
			baseDigest = ""
		}

		if _, ok := secrets[key]; ok {
			return fmt.Errorf("secret %s already exists (use 'enbu edit %s VALUE' to update it)", key, key)
		}
		secrets[key] = value

		pushOpts.ExpectedDigest = baseDigest

		a.emitStepProgress("add", "encrypt", "start")
		plaintext := bundle.Marshal(secrets)
		ciphertext, err := age.EncryptForPublicKeys(plaintext, publicKeys)
		if err != nil {
			return fmt.Errorf("encrypting secrets: %w", err)
		}

		a.emitStepProgress("add", "push", "start")
		if err := a.Registry.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, pushOpts); err != nil {
			if errors.Is(err, oci.ErrConflict) {
				if attempt < maxRetries-1 {
					a.emitRetry(attempt+1, maxRetries)
					time.Sleep(time.Duration(100+rand.IntN(100)) * time.Millisecond)
					continue
				}
				return fmt.Errorf("secrets changed by another user, failed after %d attempts", maxRetries)
			}
			return fmt.Errorf("pushing encrypted secrets: %w", err)
		}

		_ = a.Registry.Push(ctx, fmt.Sprintf("%s:%s", a.registryRef(owner, repo), snapshotTag(resolved.Name)), "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, &oci.PushOptions{SourceRepo: a.sourceRepoURL(owner, repo)})
		a.cacheAfterRemoteUpdate(secretsRef, ciphertext)
		a.emitStepProgress("add", "push", "done")
		a.emit(fmt.Sprintf("Added %s (%d secrets total)", key, len(secrets)))
		return nil
	}
	return nil
}

func (a *App) EditSecret(ctx context.Context, env, key, value string) error {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return err
	}

	accessToken, _, err := a.TokenProvider.LoadToken()
	if err != nil {
		return err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return err
	}

	identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		return fmt.Errorf("no decryption keys found (run 'enbu init' first)")
	}

	secretsRef := a.secretsRef(owner, repo, resolved.Name)
	recipientsRef := a.registryRef(owner, repo)

	publicKeys, err := PullAllRecipients(ctx, a.Registry, recipientsRef, accessToken)
	if err != nil {
		return fmt.Errorf("pulling recipients: %w", err)
	}
	if len(publicKeys) == 0 {
		return fmt.Errorf("no recipients found (has anyone run 'enbu init'?)")
	}

	pushOpts := &oci.PushOptions{
		SourceRepo: a.sourceRepoURL(owner, repo),
	}

	for attempt := range maxRetries {
		secrets, baseDigest, err := PullSecretsWithDigest(ctx, a.Registry, secretsRef, accessToken, identities...)
		if err != nil {
			if IsNotFoundError(err) {
				return fmt.Errorf("secret %s does not exist (use 'enbu add %s VALUE' to create it)", key, key)
			}
			return fmt.Errorf("pulling secrets: %w", err)
		}

		if _, ok := secrets[key]; !ok {
			return fmt.Errorf("secret %s does not exist (use 'enbu add %s VALUE' to create it)", key, key)
		}
		secrets[key] = value

		pushOpts.ExpectedDigest = baseDigest

		plaintext := bundle.Marshal(secrets)
		ciphertext, err := age.EncryptForPublicKeys(plaintext, publicKeys)
		if err != nil {
			return fmt.Errorf("encrypting secrets: %w", err)
		}

		if err := a.Registry.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, pushOpts); err != nil {
			if errors.Is(err, oci.ErrConflict) {
				if attempt < maxRetries-1 {
					a.emitRetry(attempt+1, maxRetries)
					continue
				}
				return fmt.Errorf("secrets changed by another user, failed after %d attempts", maxRetries)
			}
			return fmt.Errorf("pushing encrypted secrets: %w", err)
		}

		_ = a.Registry.Push(ctx, fmt.Sprintf("%s:%s", a.registryRef(owner, repo), snapshotTag(resolved.Name)), "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, &oci.PushOptions{SourceRepo: a.sourceRepoURL(owner, repo)})
		a.cacheAfterRemoteUpdate(secretsRef, ciphertext)
		a.emit(fmt.Sprintf("Updated %s (%d secrets total)", key, len(secrets)))
		return nil
	}
	return nil
}

func (a *App) DeleteSecret(ctx context.Context, env, key string) error {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return err
	}

	accessToken, _, err := a.TokenProvider.LoadToken()
	if err != nil {
		return err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return err
	}

	identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		return fmt.Errorf("no decryption keys found (run 'enbu init' first)")
	}

	secretsRef := a.secretsRef(owner, repo, resolved.Name)
	recipientsRef := a.registryRef(owner, repo)

	a.emitStepProgress("delete", "pull_recipients", "start")
	publicKeys, err := PullAllRecipients(ctx, a.Registry, recipientsRef, accessToken)
	if err != nil {
		return fmt.Errorf("pulling recipients: %w", err)
	}
	if len(publicKeys) == 0 {
		return fmt.Errorf("no recipients found (has anyone run 'enbu init'?)")
	}

	pushOpts := &oci.PushOptions{
		SourceRepo: a.sourceRepoURL(owner, repo),
	}

	for attempt := range maxRetries {
		a.emitStepProgress("delete", "pull_secrets", "start")
		secrets, baseDigest, ciphertext, err := pullSecretsWithDigestAndCiphertext(ctx, a.Registry, secretsRef, accessToken, identities...)
		if err != nil {
			if IsNotFoundError(err) {
				if err := a.refreshSecretCache(secretsRef, nil); err != nil {
					return fmt.Errorf("recording empty remote secrets: %w", err)
				}
				a.emitStepProgress("delete", "pull_secrets", "done")
				return nil
			}
			return fmt.Errorf("pulling secrets: %w", err)
		}

		if _, ok := secrets[key]; !ok {
			if err := a.refreshSecretCache(secretsRef, ciphertext); err != nil {
				return fmt.Errorf("refreshing secrets after delete no-op: %w", err)
			}
			a.emitStepProgress("delete", "pull_secrets", "done")
			return nil
		}
		delete(secrets, key)

		pushOpts.ExpectedDigest = baseDigest

		a.emitStepProgress("delete", "encrypt", "start")
		plaintext := bundle.Marshal(secrets)
		ciphertext, err = age.EncryptForPublicKeys(plaintext, publicKeys)
		if err != nil {
			return fmt.Errorf("encrypting secrets: %w", err)
		}

		a.emitStepProgress("delete", "push", "start")
		if err := a.Registry.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, pushOpts); err != nil {
			if errors.Is(err, oci.ErrConflict) {
				if attempt < maxRetries-1 {
					a.emitRetry(attempt+1, maxRetries)
					continue
				}
				return fmt.Errorf("secrets changed by another user, failed after %d attempts", maxRetries)
			}
			return fmt.Errorf("pushing encrypted secrets: %w", err)
		}

		_ = a.Registry.Push(ctx, fmt.Sprintf("%s:%s", a.registryRef(owner, repo), snapshotTag(resolved.Name)), "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, &oci.PushOptions{SourceRepo: a.sourceRepoURL(owner, repo)})
		a.cacheAfterRemoteUpdate(secretsRef, ciphertext)
		a.emitStepProgress("delete", "push", "done")
		a.emit(fmt.Sprintf("Deleted %s (%d secrets remaining)", key, len(secrets)))
		return nil
	}
	return nil
}

func (a *App) PullSecrets(ctx context.Context, env string) (int, bool, error) {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return 0, false, err
	}

	accessToken, _, err := a.TokenProvider.LoadToken()
	if err != nil {
		return 0, false, err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return 0, false, err
	}

	ref := a.secretsRef(owner, repo, resolved.Name)

	a.emitStepProgress("pull", "download", "start")
	ciphertext, err := a.Registry.Pull(ctx, ref, accessToken)
	if err != nil {
		if IsNotFoundError(err) {
			if err := a.refreshSecretCache(ref, nil); err != nil {
				return 0, false, fmt.Errorf("recording empty remote secrets: %w", err)
			}
			a.emitStepProgress("pull", "download", "done")
			a.emit("No secrets have been uploaded for this environment.")
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("pulling secrets: %w", err)
	}
	a.emitStepProgress("pull", "download", "done")

	identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
	if err != nil {
		return 0, false, err
	}
	if len(identities) == 0 {
		return 0, false, fmt.Errorf("no decryption keys found (run 'enbu init' first)")
	}

	a.emitStepProgress("pull", "validate", "start")
	secrets, err := decryptSecretBundle(ciphertext, identities...)
	if err != nil {
		return 0, false, fmt.Errorf("validating secrets: %w", err)
	}
	a.emitStepProgress("pull", "validate", "done")

	a.emitStepProgress("pull", "cache", "start")
	if err := a.secretCache().Store(ref, ciphertext); err != nil {
		return 0, false, fmt.Errorf("caching secrets: %w", err)
	}
	a.emitStepProgress("pull", "cache", "done")
	a.emit(fmt.Sprintf("Pulled %d secrets", len(secrets)))
	return len(secrets), true, nil
}

func (a *App) refreshSecretCache(ref string, ciphertext []byte) error {
	cache := a.secretCache()
	if err := cache.Store(ref, ciphertext); err != nil {
		if deleteErr := cache.Delete(ref); deleteErr != nil {
			return fmt.Errorf("storing current state: %w; invalidating stale state: %v", err, deleteErr)
		}
		return fmt.Errorf("storing current state: %w", err)
	}
	return nil
}

var errConflict = errors.New("secrets changed by another user")

func (a *App) SyncSecrets(ctx context.Context, env string) error {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return err
	}

	accessToken, _, err := a.TokenProvider.LoadToken()
	if err != nil {
		return err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return err
	}

	identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		return fmt.Errorf("no decryption keys found (run 'enbu init' first)")
	}

	secretsRef := a.secretsRef(owner, repo, resolved.Name)
	recipientsRef := a.registryRef(owner, repo)
	pushOpts := &oci.PushOptions{
		SourceRepo: a.sourceRepoURL(owner, repo),
	}

	const syncMaxRetries = 5
	backoff := 1 * time.Second

	for attempt := range syncMaxRetries {
		err := a.doSync(ctx, secretsRef, recipientsRef, accessToken, identities, pushOpts)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errConflict) {
			return err
		}
		if attempt == syncMaxRetries-1 {
			return fmt.Errorf("sync failed after %d attempts: %w", syncMaxRetries, err)
		}

		a.emitRetry(attempt+1, syncMaxRetries)

		jitter := time.Duration(rand.Int64N(int64(backoff / 2)))
		wait := backoff + jitter

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		backoff *= 2
	}
	return nil
}

func (a *App) doSync(ctx context.Context, secretsRef, recipientsRef, token string, identities []agecrypto.Identity, pushOpts *oci.PushOptions) error {
	a.emitStepProgress("sync", "pull_secrets", "start")
	secrets, baseDigest, err := PullSecretsWithDigest(ctx, a.Registry, secretsRef, token, identities...)
	if err != nil {
		if IsNotFoundError(err) {
			a.emitStepProgress("sync", "pull_secrets", "done")
			a.emit("No secrets found, nothing to sync.")
			return nil
		}
		return fmt.Errorf("pulling secrets: %w", err)
	}

	a.emitStepProgress("sync", "pull_recipients", "start")
	publicKeys, err := PullAllRecipients(ctx, a.Registry, recipientsRef, token)
	if err != nil {
		return fmt.Errorf("pulling recipients: %w", err)
	}
	if len(publicKeys) == 0 {
		return fmt.Errorf("no recipients found")
	}

	if baseDigest != "" {
		currentDigest, err := a.Registry.GetDigest(ctx, secretsRef, token)
		if err == nil && currentDigest != baseDigest {
			return fmt.Errorf("%w", errConflict)
		}
	}

	a.emitStepProgress("sync", "reencrypt", "start")
	plaintext := bundle.Marshal(secrets)
	ciphertext, err := age.EncryptForPublicKeys(plaintext, publicKeys)
	if err != nil {
		return fmt.Errorf("encrypting secrets: %w", err)
	}

	a.emitStepProgress("sync", "push", "start")
	if err := a.Registry.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, token, pushOpts); err != nil {
		return fmt.Errorf("pushing encrypted secrets: %w", err)
	}

	a.cacheAfterRemoteUpdate(secretsRef, ciphertext)
	a.emitStepProgress("sync", "push", "done")
	a.emit(fmt.Sprintf("Synchronized secrets for %d recipients (%d secrets)", len(publicKeys), len(secrets)))
	return nil
}

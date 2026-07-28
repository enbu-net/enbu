package app

import (
	"context"
	agecrypto "filippo.io/age"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/enbu-net/enbu/apperr"
	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/bundle"
	"github.com/enbu-net/enbu/utils/oci"
)

const maxRetries = 3

func (a *App) ListSecrets(ctx context.Context, env string) (result map[string]string, err error) {
	defer apperr.NormalizeInto(&err)

	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}

	accessToken, _, err := a.TokenProvider.LoadToken()
	if err != nil {
		return nil, err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return nil, err
	}

	identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
	if err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no decryption keys found (run 'enbu init' first)")
	}

	secretsRef := a.secretsRef(owner, repo, resolved.Name)

	secrets, _, err := PullSecretsWithDigest(ctx, a.Registry, secretsRef, accessToken, identities...)
	if err != nil {
		if IsNotFoundError(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("pulling secrets: %w", err)
	}

	return secrets, nil
}

func (a *App) AddSecret(ctx context.Context, env, key, value string) (err error) {
	defer apperr.NormalizeInto(&err)

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
			return apperr.New(apperr.CodeSecretExists, fmt.Sprintf("secret %s already exists (use 'enbu edit %s VALUE' to update it)", key, key), apperr.Params{"key": key})
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
			if apperr.Is(err, apperr.CodeConflict) {
				if attempt < maxRetries-1 {
					a.emitRetry(attempt+1, maxRetries)
					time.Sleep(time.Duration(100+rand.IntN(100)) * time.Millisecond)
					continue
				}
				return conflictRetriesExhausted(err, maxRetries)
			}
			return fmt.Errorf("pushing encrypted secrets: %w", err)
		}

		_ = a.Registry.Push(ctx, fmt.Sprintf("%s:%s", a.registryRef(owner, repo), snapshotTag(resolved.Name)), "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, &oci.PushOptions{SourceRepo: a.sourceRepoURL(owner, repo)})
		a.emitStepProgress("add", "push", "done")
		a.emit(fmt.Sprintf("Added %s (%d secrets total)", key, len(secrets)))
		return nil
	}
	return nil
}

func (a *App) EditSecret(ctx context.Context, env, key, value string) (err error) {
	defer apperr.NormalizeInto(&err)

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
			return fmt.Errorf("pulling secrets: %w", err)
		}

		if _, ok := secrets[key]; !ok {
			return apperr.New(apperr.CodeSecretMissing, fmt.Sprintf("secret %s does not exist (use 'enbu add %s VALUE' to create it)", key, key), apperr.Params{"key": key})
		}
		secrets[key] = value

		pushOpts.ExpectedDigest = baseDigest

		plaintext := bundle.Marshal(secrets)
		ciphertext, err := age.EncryptForPublicKeys(plaintext, publicKeys)
		if err != nil {
			return fmt.Errorf("encrypting secrets: %w", err)
		}

		if err := a.Registry.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, pushOpts); err != nil {
			if apperr.Is(err, apperr.CodeConflict) {
				if attempt < maxRetries-1 {
					a.emitRetry(attempt+1, maxRetries)
					continue
				}
				return conflictRetriesExhausted(err, maxRetries)
			}
			return fmt.Errorf("pushing encrypted secrets: %w", err)
		}

		_ = a.Registry.Push(ctx, fmt.Sprintf("%s:%s", a.registryRef(owner, repo), snapshotTag(resolved.Name)), "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, &oci.PushOptions{SourceRepo: a.sourceRepoURL(owner, repo)})
		a.emit(fmt.Sprintf("Updated %s (%d secrets total)", key, len(secrets)))
		return nil
	}
	return nil
}

func (a *App) DeleteSecret(ctx context.Context, env, key string) (err error) {
	defer apperr.NormalizeInto(&err)

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
		secrets, baseDigest, err := PullSecretsWithDigest(ctx, a.Registry, secretsRef, accessToken, identities...)
		if err != nil {
			if IsNotFoundError(err) {
				a.emitStepProgress("delete", "pull_secrets", "done")
				return nil
			}
			return fmt.Errorf("pulling secrets: %w", err)
		}

		if _, ok := secrets[key]; !ok {
			a.emitStepProgress("delete", "pull_secrets", "done")
			return nil
		}
		delete(secrets, key)

		pushOpts.ExpectedDigest = baseDigest

		a.emitStepProgress("delete", "encrypt", "start")
		plaintext := bundle.Marshal(secrets)
		ciphertext, err := age.EncryptForPublicKeys(plaintext, publicKeys)
		if err != nil {
			return fmt.Errorf("encrypting secrets: %w", err)
		}

		a.emitStepProgress("delete", "push", "start")
		if err := a.Registry.Push(ctx, secretsRef, "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, pushOpts); err != nil {
			if apperr.Is(err, apperr.CodeConflict) {
				if attempt < maxRetries-1 {
					a.emitRetry(attempt+1, maxRetries)
					continue
				}
				return conflictRetriesExhausted(err, maxRetries)
			}
			return fmt.Errorf("pushing encrypted secrets: %w", err)
		}

		_ = a.Registry.Push(ctx, fmt.Sprintf("%s:%s", a.registryRef(owner, repo), snapshotTag(resolved.Name)), "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, &oci.PushOptions{SourceRepo: a.sourceRepoURL(owner, repo)})
		a.emitStepProgress("delete", "push", "done")
		a.emit(fmt.Sprintf("Deleted %s (%d secrets remaining)", key, len(secrets)))
		return nil
	}
	return nil
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
	return bundle.ToDotEnv(result.Secrets), result.Output, len(result.Secrets), nil
}

func (a *App) pullSecretsData(ctx context.Context, env string, emitDone bool) (*PulledSecrets, error) {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}

	accessToken, _, err := a.TokenProvider.LoadToken()
	if err != nil {
		return nil, err
	}

	owner, repo, err := a.RepoDetector.LoadRepo()
	if err != nil {
		return nil, err
	}

	ref := a.secretsRef(owner, repo, resolved.Name)

	a.emitStepProgress("pull", "pull_secrets", "start")
	ciphertext, err := a.Registry.Pull(ctx, ref, accessToken)
	if err != nil {
		return nil, fmt.Errorf("pulling secrets: %w", err)
	}

	identities, err := LoadIdentitiesForRepo(a.KeyStore, owner, repo)
	if err != nil {
		return nil, err
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no decryption keys found (run 'enbu init' first)")
	}

	a.emitStepProgress("pull", "decrypt", "start")
	plaintext, err := age.Decrypt(ciphertext, identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting secrets: %w", err)
	}

	secrets, err := bundle.Unmarshal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parsing secrets: %w", err)
	}

	if emitDone {
		a.emitStepProgress("pull", "decrypt", "done")
	}
	return &PulledSecrets{
		Environment: resolved.Name,
		Output:      resolved.Output,
		Secrets:     secrets,
	}, nil
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
	if err := os.WriteFile(outputPath, bundle.ToDotEnv(result.Secrets), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", result.Output, err)
	}

	a.emitStepProgress("pull", "write", "done")
	a.emit(fmt.Sprintf("Written %s (%d secrets)", result.Output, len(result.Secrets)))
	return nil
}

func (a *App) SyncSecrets(ctx context.Context, env string) (err error) {
	defer apperr.NormalizeInto(&err)

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
		if !apperr.Is(err, apperr.CodeConflict) {
			return err
		}
		if attempt == syncMaxRetries-1 {
			return conflictRetriesExhausted(err, syncMaxRetries)
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
			return apperr.New(apperr.CodeConflict, "secrets changed by another user", nil)
		}
	}
	pushOpts.ExpectedDigest = baseDigest

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

	a.emitStepProgress("sync", "push", "done")
	a.emit(fmt.Sprintf("Synchronized secrets for %d recipients (%d secrets)", len(publicKeys), len(secrets)))
	return nil
}

func conflictRetriesExhausted(err error, attempts int) error {
	return fmt.Errorf("secrets changed by another user, failed after %d attempts: %w", attempts, err)
}

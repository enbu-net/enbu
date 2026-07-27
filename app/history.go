package app

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"time"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/bundle"
	"github.com/enbu-net/enbu/utils/oci"
)

type HistoryEntry struct {
	Index     int
	Timestamp time.Time
	Tag       string
}

type Diff struct {
	Added    []string
	Removed  []string
	Modified []string
}

func (a *App) ListHistory(ctx context.Context, env string) ([]HistoryEntry, error) {
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

	ref := a.registryRef(owner, repo)
	tags, err := a.Registry.ListTags(ctx, ref, accessToken)
	if err != nil {
		if IsNotFoundError(err) {
			return []HistoryEntry{}, nil
		}
		return nil, fmt.Errorf("listing tags: %w", err)
	}

	var entries []HistoryEntry
	for _, tag := range tags {
		if !IsSnapshotTag(resolved.Name, tag) {
			continue
		}
		ts, ok := snapshotTimestamp(resolved.Name, tag)
		if !ok {
			continue
		}
		entries = append(entries, HistoryEntry{Tag: tag, Timestamp: ts})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	for i := range entries {
		entries[i].Index = i + 1
	}

	return entries, nil
}

func (a *App) DiffHistory(ctx context.Context, env string, fromIdx, toIdx int) (*Diff, error) {
	entries, err := a.ListHistory(ctx, env)
	if err != nil {
		return nil, err
	}

	if fromIdx < 1 || fromIdx > len(entries) {
		return nil, fmt.Errorf("version %d not found (history has %d entries)", fromIdx, len(entries))
	}
	if toIdx < 1 || toIdx > len(entries) {
		return nil, fmt.Errorf("version %d not found (history has %d entries)", toIdx, len(entries))
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

	ref := a.registryRef(owner, repo)
	fromRef := fmt.Sprintf("%s:%s", ref, entries[fromIdx-1].Tag)
	toRef := fmt.Sprintf("%s:%s", ref, entries[toIdx-1].Tag)

	fromSecrets, err := pullAndDecrypt(ctx, a.Registry, fromRef, accessToken, identities)
	if err != nil {
		return nil, fmt.Errorf("pulling version %d: %w", fromIdx, err)
	}

	toSecrets, err := pullAndDecrypt(ctx, a.Registry, toRef, accessToken, identities)
	if err != nil {
		return nil, fmt.Errorf("pulling version %d: %w", toIdx, err)
	}

	return diffSecrets(fromSecrets, toSecrets), nil
}

func (a *App) RestoreHistory(ctx context.Context, env string, idx int) error {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return err
	}

	entries, err := a.ListHistory(ctx, env)
	if err != nil {
		return err
	}

	if idx < 1 || idx > len(entries) {
		return fmt.Errorf("version %d not found (history has %d entries)", idx, len(entries))
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

	ref := a.registryRef(owner, repo)
	snapshotRef := fmt.Sprintf("%s:%s", ref, entries[idx-1].Tag)

	secrets, err := pullAndDecrypt(ctx, a.Registry, snapshotRef, accessToken, identities)
	if err != nil {
		return fmt.Errorf("pulling snapshot: %w", err)
	}

	publicKeys, err := PullAllRecipients(ctx, a.Registry, ref, accessToken)
	if err != nil {
		return fmt.Errorf("pulling recipients: %w", err)
	}
	if len(publicKeys) == 0 {
		return fmt.Errorf("no recipients found (has anyone run 'enbu init'?)")
	}

	secretsRef := a.secretsRef(owner, repo, resolved.Name)
	pushOpts := &oci.PushOptions{SourceRepo: a.sourceRepoURL(owner, repo)}

	for attempt := range maxRetries {
		baseDigest, err := a.Registry.GetDigest(ctx, secretsRef, accessToken)
		if err != nil && !IsNotFoundError(err) {
			return fmt.Errorf("getting current digest: %w", err)
		}
		if IsNotFoundError(err) {
			baseDigest = ""
		}
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
					time.Sleep(time.Duration(100+rand.IntN(100)) * time.Millisecond)
					continue
				}
				return fmt.Errorf("secrets changed by another user, failed after %d attempts", maxRetries)
			}
			return fmt.Errorf("pushing restored secrets: %w", err)
		}

		snapshotPushRef := fmt.Sprintf("%s:%s", ref, snapshotTag(resolved.Name))
		_ = a.Registry.Push(ctx, snapshotPushRef, "application/vnd.enbu.secrets.age.v1", ciphertext, accessToken, &oci.PushOptions{SourceRepo: a.sourceRepoURL(owner, repo)})

		a.cacheAfterRemoteUpdate(secretsRef, ciphertext)
		a.emit(fmt.Sprintf("Restored secrets--%s to version %d (%s)", resolved.Name, idx, entries[idx-1].Timestamp.Format("2006-01-02 15:04:05")))
		return nil
	}
	return nil
}

func pullAndDecrypt(ctx context.Context, reg Registry, ref, token string, identities []agecrypto.Identity) (map[string]string, error) {
	ciphertext, err := reg.Pull(ctx, ref, token)
	if err != nil {
		return nil, err
	}

	plaintext, err := age.Decrypt(ciphertext, identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	secrets, err := bundle.Unmarshal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}

	return secrets, nil
}

func diffSecrets(from, to map[string]string) *Diff {
	d := &Diff{}
	for k := range to {
		if _, ok := from[k]; !ok {
			d.Added = append(d.Added, k)
		} else if from[k] != to[k] {
			d.Modified = append(d.Modified, k)
		}
	}
	for k := range from {
		if _, ok := to[k]; !ok {
			d.Removed = append(d.Removed, k)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Modified)
	return d
}

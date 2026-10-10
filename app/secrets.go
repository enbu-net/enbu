package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/bundle"
	"github.com/enbu-net/enbu/pkg/merge"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

const maxRetries = 3

var errNoChange = fmt.Errorf("secret unchanged")

func (a *App) ListSecrets(ctx context.Context, env string) (result map[string]string, err error) {
	defer apperr.NormalizeInto(&err)
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	read, err := s.readResource(ctx, resolved.Name, nil, true)
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

// SecretConflict is a key that concurrent edits changed differently. Nothing
// is chosen for the user: they pick one candidate, or give a new value.
type SecretConflict struct {
	Key        string              `json:"key"`
	Candidates []ConflictCandidate `json:"candidates"`
}

type ConflictCandidate struct {
	Value   string `json:"value"`
	Deleted bool   `json:"deleted"`
}

// ConflictSet is what a person looked at when deciding: the conflicted keys and
// the heads they were computed from. ResolveSecrets must be given the same
// Heads, so a value that appeared since is shown to the person rather than
// swept away by a choice made without seeing it.
type ConflictSet struct {
	// ID is a short name for Heads, for a person to repeat back when deciding.
	ID        string           `json:"id"`
	Heads     []string         `json:"heads"`
	Conflicts []SecretConflict `json:"conflicts"`
}

// ListConflicts returns the keys of env that are waiting for a decision.
func (a *App) ListConflicts(ctx context.Context, env string) (set *ConflictSet, err error) {
	defer apperr.NormalizeInto(&err)
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	read, err := s.readResource(ctx, resolved.Name, nil, true)
	if IsNotFoundError(err) {
		return &ConflictSet{}, nil
	}
	if err != nil {
		return nil, err
	}
	heads := headNames(read.parents())
	return &ConflictSet{ID: conflictID(heads), Heads: heads, Conflicts: toSecretConflicts(read.conflicts)}, nil
}

func conflictID(heads []string) string {
	sum := sha256.Sum256([]byte(strings.Join(heads, "\n")))
	return hex.EncodeToString(sum[:])[:12]
}

func headNames(heads []digest.Digest) []string {
	out := make([]string, len(heads))
	for i, h := range heads {
		out[i] = h.Encoded()
	}
	slices.Sort(out)
	return out
}

// SecretChoice settles one conflicted key with a value, or by deleting it.
type SecretChoice struct {
	Value  string
	Delete bool
}

// ResolveSecrets settles every conflicted key of env and publishes the result
// as a revision that merges all heads. Every conflict must be settled at once:
// a merge revision holds one value per key. seen is ConflictSet.Heads from the
// listing the choices were made from; if the heads are different now, nothing
// is published and the person looks again.
func (a *App) ResolveSecrets(ctx context.Context, env string, seen []string, choices map[string]SecretChoice) (err error) {
	defer apperr.NormalizeInto(&err)
	if len(seen) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "resolving needs the heads of the conflicts that were listed", nil)
	}
	slices.Sort(seen)
	picked := make(map[string]merge.Choice, len(choices))
	for k, c := range choices {
		picked[k] = merge.Choice{Value: c.Value, Delete: c.Delete}
	}
	return a.changeSecretWith(ctx, env, "resolve", picked, seen, func(map[string]string) error { return nil })
}

func toSecretConflicts(cs []merge.Conflict) []SecretConflict {
	out := make([]SecretConflict, len(cs))
	for i, c := range cs {
		out[i] = SecretConflict{Key: c.Key}
		for _, v := range c.Candidates {
			out[i].Candidates = append(out[i].Candidates, ConflictCandidate{Value: v.Text, Deleted: v.Deleted})
		}
	}
	return out
}

func conflictError(cs []merge.Conflict) error {
	if len(cs) == 0 {
		return nil
	}
	keys := make([]string, len(cs))
	for i, c := range cs {
		keys[i] = c.Key
	}
	return apperr.New(apperr.CodeSecretConflict, fmt.Sprintf("concurrent edits changed %s differently; choose a value with 'enbu resolve'", strings.Join(keys, ", ")),
		apperr.Params{"keys": strings.Join(keys, ", ")})
}

func (a *App) changeSecret(ctx context.Context, env, op string, change func(map[string]string) error) error {
	return a.changeSecretWith(ctx, env, op, nil, nil, change)
}

// changeSecretWith reads the merged content, applies change, and publishes the
// result as a new revision whose parents are every head it saw. It never
// overwrites: if another writer published meanwhile, both revisions exist and
// whichever reads next merges them. Before publishing it looks once more, so a
// head that appeared during the edit is merged now rather than left for later.
func (a *App) changeSecretWith(ctx context.Context, env, op string, choices map[string]merge.Choice, seen []string, change func(map[string]string) error) error {
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return err
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return err
	}
	defer func() { // s is replaced when the member list changes
		if s != nil {
			s.Close()
		}
	}()
	attempts := maxRetries
	if op == "sync" {
		attempts = 5
	}
	var published []digest.Digest // revisions this call made; a stale listing may not show them yet
	for attempt := 0; attempt < attempts; attempt++ {
		a.emitStepProgress(op, "pull_secrets", "start")
		cur, err := s.readResource(ctx, resolved.Name, choices, true, published...)
		var secrets map[string]string
		var parents []digest.Digest
		if err != nil {
			if !IsNotFoundError(err) {
				return fmt.Errorf("pulling secrets: %w", err)
			}
			if op == "sync" || op == "delete" {
				a.emitStepProgress(op, "pull_secrets", "done")
				return nil
			}
			if op == "edit" || op == "resolve" {
				return err
			}
			secrets = map[string]string{}
		} else {
			if seen != nil && !slices.Equal(headNames(cur.parents()), seen) {
				return apperr.New(apperr.CodeConflict, "the conflicts changed since you looked at them; run 'enbu resolve' again to see the new values", nil)
			}
			if err := conflictError(cur.conflicts); err != nil {
				return err
			}
			secrets, parents = maps.Clone(cur.secrets), cur.parents()
		}
		if err := change(secrets); err != nil {
			if err == errNoChange && len(parents) <= 1 {
				a.emitStepProgress(op, "pull_secrets", "done")
				return nil
			}
			if err != errNoChange {
				return err
			}
		}
		// Look once more just before publishing: heads that appeared during the
		// edit are merged now, in the same revision.
		if cur != nil {
			latest, err := s.loadResource(ctx, resolved.Name, published...)
			if err != nil {
				return err
			}
			accepted, err := s.cps.State(s.resource(resolved.Name))
			if err != nil {
				return err
			}
			if !sameHeads(s.trustedHeads(latest, accepted), cur.heads) {
				a.emitRetry(attempt+1, attempts)
				continue
			}
		}
		a.emitStepProgress(op, "encrypt", "start")
		a.emitStepProgress(op, "push", "start")
		rev, err := s.writeState(ctx, resolved.Name, secrets, parents)
		if rev != "" {
			published = append(published, rev)
		}
		if errors.Is(err, errControlMoved) {
			// Members changed while we were working. Start over on the new member
			// list so removed members are not encrypted for; a revision already
			// published stays and is merged by the next read.
			s.Close()
			if s, err = a.openSession(ctx); err != nil {
				return err
			}
			if attempt == attempts-1 {
				return fmt.Errorf("workspace members kept changing: %w", errControlMoved)
			}
			continue
		}
		if errors.Is(err, storage.ErrNotFound) {
			// A blob vanished between its upload and the read-back (registry GC).
			// Run the whole attempt again, which uploads it again.
			if attempt == attempts-1 {
				return fmt.Errorf("saving encrypted secrets: uploaded blob disappeared before it was referenced: %v", err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("saving encrypted secrets: %w", err)
		}
		if err := s.acceptPublished(ctx, resolved.Name, rev); err != nil {
			return err
		}
		a.emitStepProgress(op, "push", "done")
		return nil
	}
	return apperr.New(apperr.CodeConflict, fmt.Sprintf("secrets changed by other users while saving; failed after %d attempts", attempts), nil)
}

func sameHeads(a, b []*wsp.VerifiedState) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Digest != b[i].Digest {
			return false
		}
	}
	return true
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
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	a.emitStepProgress("pull", "pull_secrets", "start")
	a.emitStepProgress("pull", "decrypt", "start")
	read, err := s.readResource(ctx, resolved.Name, nil, true)
	if err != nil {
		return nil, fmt.Errorf("pulling secrets: %w", err)
	}
	if err := conflictError(read.conflicts); err != nil {
		return nil, err
	}
	secrets := read.secrets
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

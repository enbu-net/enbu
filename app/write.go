package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/merge"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

const maxRetries = 3

func (a *App) changeSecret(ctx context.Context, env, op string, change func(map[string]string) error) error {
	return a.changeSecretWith(ctx, env, op, nil, nil, change)
}

// changeSecretWith reads the merged content, applies change, and publishes the
// result as a new revision whose parents are every head it saw. It never
// overwrites: if another writer published meanwhile, both revisions exist and
// whichever reads next merges them. Before publishing it looks once more, so a
// head that appeared during the edit is merged now rather than left for later.
func (a *App) changeSecretWith(ctx context.Context, env, op string, choices map[string]merge.Choice, seen []string, change func(map[string]string) error) error {
	s, resolved, err := a.openEnvironment(ctx, env)
	if err != nil {
		return err
	}
	return a.changeResource(ctx, s, s.resource(resolved.Name), op, choices, seen, change)
}

// changeResource is changeSecretWith for one storage resource. It takes over s
// and closes it.
func (a *App) changeResource(ctx context.Context, s *session, resource, op string, choices map[string]merge.Choice, seen []string, change func(map[string]string) error) error {
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
		cur, err := s.readResource(ctx, resource, choices, true, published...)
		var secrets map[string]string
		var parents []*wsp.VerifiedState
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
			secrets, parents = maps.Clone(cur.secrets), cur.heads
		}
		// A membership change after Publish may restart this call. If one
		// of our revisions is already in the trusted result, its mutation has
		// committed; applying it again would turn a successful add into a
		// duplicate error or overwrite a later writer's work.
		if !publishedInRead(cur, published) {
			if err := change(secrets); err != nil {
				if err == errNoChange && len(parents) <= 1 {
					a.emitStepProgress(op, "pull_secrets", "done")
					return nil
				}
				if err != errNoChange {
					return err
				}
			}
		}
		// Look once more just before publishing: heads that appeared during the
		// edit are merged now, in the same revision.
		var latest *wsp.StateView
		if cur != nil {
			latest, err = s.loadResource(ctx, resource, published...)
			if err != nil {
				return err
			}
			if !sameHeads(s.trustedHeads(latest), cur.heads) {
				a.emitRetry(attempt+1, attempts)
				continue
			}
		}
		a.emitStepProgress(op, "encrypt", "start")
		a.emitStepProgress(op, "push", "start")
		st, err := s.writeState(ctx, resource, stateOp(op), secrets, parents)
		if st != nil {
			published = append(published, st.Digest)
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
		if err != nil {
			return fmt.Errorf("saving encrypted secrets: %w", err)
		}
		if err := s.acceptPublished(ctx, resource, st); err != nil {
			return err
		}
		a.emitStepProgress(op, "push", "done")
		return nil
	}
	return apperr.New(apperr.CodeConflict, fmt.Sprintf("secrets changed by other users while saving; failed after %d attempts", attempts), nil)
}

// stateOp is the kind of revision an operation publishes.
func stateOp(op string) string {
	switch op {
	case "sync":
		return wsp.OpSync
	case "restore":
		return wsp.OpRestore
	case "resolve":
		return wsp.OpResolve
	}
	return wsp.OpWrite
}

func publishedInRead(read *resourceRead, published []digest.Digest) bool {
	if read == nil {
		return false
	}
	for _, head := range read.heads {
		ancestors := read.view.Graph.Ancestors(head.Digest)
		for _, revision := range published {
			if ancestors[revision] {
				return true
			}
		}
	}
	return false
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

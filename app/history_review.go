package app

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// ReviewRemovedRevision previews the merge of a verified, set-aside revision
// with current heads. An admin can publish the merge directly so the recovery
// is independent of any readers updating their local checkpoints.
func (a *App) ReviewRemovedRevision(ctx context.Context, env, revision string, apply bool) (_ *Diff, err error) {
	defer apperr.NormalizeInto(&err)
	d, err := digest.Parse(revision)
	if err != nil || d.Algorithm() != digest.SHA256 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "a full SHA-256 revision digest is required", nil)
	}
	s, resource, err := a.openReviewResource(ctx, env)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if p, _ := s.head.Principal(s.self()); !p.Admin {
		return nil, apperr.New(apperr.CodeAccessDenied, "only a workspace admin can review set-aside revisions", nil)
	}
	view, err := s.loadResource(ctx, resource)
	if err != nil {
		return nil, err
	}
	accepted, err := s.cps.Accepted(resource)
	if err != nil {
		return nil, err
	}
	heads := s.trustedHeads(view, accepted)
	if !slices.ContainsFunc(view.Heads, func(head *wsp.VerifiedState) bool { return head.Digest == d }) ||
		historyStates(view, heads)[d] != nil || !view.Compacted.AboveFloors(view.Graph, d) ||
		wsp.AuthorIsCurrent(s.view, s.head, view.States[d]) == nil {
		return nil, apperr.New(apperr.CodeConflict, "the revision is no longer awaiting review", nil)
	}
	var current map[string]string
	if len(heads) != 0 {
		read, err := s.mergeResourceHeads(ctx, resource, view, heads, nil)
		if err != nil {
			return nil, err
		}
		if err := conflictError(read.conflicts); err != nil {
			return nil, err
		}
		current = read.secrets
	}
	// Heads already covered by the reviewed revision are ancestors, so the
	// regular merge should not compare their older values as separate branches.
	ancestors := view.Graph.Ancestors(d)
	reviewHeads := slices.DeleteFunc(slices.Clone(heads), func(h *wsp.VerifiedState) bool {
		return ancestors[h.Digest]
	})
	merged, err := s.mergeResourceHeads(ctx, resource, view, append(reviewHeads, view.States[d]), nil)
	if err != nil {
		return nil, err
	}
	if len(merged.conflicts) != 0 {
		keys := make([]string, len(merged.conflicts))
		for i, c := range merged.conflicts {
			keys[i] = c.Key
		}
		return nil, apperr.New(apperr.CodeRemovalReviewConflict, "the reviewed revision conflicts with current values", apperr.Params{"keys": strings.Join(keys, ", ")})
	}
	if apply {
		// The normal write fence checks Control again before publishing. A
		// role change during the review requires reopening with the new Control.
		st, err := s.writeState(ctx, resource, merged.secrets, merged.parents())
		if errors.Is(err, errControlMoved) {
			return nil, apperr.Wrap(apperr.CodeConflict, "workspace members changed during recovery", err, nil)
		}
		if err != nil {
			return nil, err
		}
		if err := s.acceptPublished(ctx, resource, st); err != nil {
			return nil, err
		}
	}
	return diffSecrets(current, merged.secrets), nil
}

func (a *App) openReviewResource(ctx context.Context, env string) (*session, string, error) {
	if id, raw := strings.CutPrefix(env, "secrets/"); raw {
		if !config.ValidEnvironmentName(id) {
			return nil, "", apperr.New(apperr.CodeInvalidArgument, "invalid secrets resource", nil)
		}
		s, err := a.openSession(ctx)
		return s, env, err
	}
	s, resolved, err := a.openEnvironment(ctx, env)
	if err != nil {
		return nil, "", err
	}
	return s, s.resource(resolved.Name), nil
}

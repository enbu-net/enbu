package app

import (
	"context"
	"slices"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// ReviewRemovedRevision compares a set-aside revision with the current
// contents. An explicit admin acceptance makes it eligible for the normal
// merge on this device, including conflict handling, before it can be signed
// again for the current member list.
func (a *App) ReviewRemovedRevision(ctx context.Context, env, revision string, accept bool) (_ *Diff, err error) {
	defer apperr.NormalizeInto(&err)
	d, err := digest.Parse(revision)
	if err != nil || d.Algorithm() != digest.SHA256 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "a full SHA-256 revision digest is required", nil)
	}
	s, resolved, err := a.openEnvironment(ctx, env)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if p, _ := s.head.Principal(s.self()); !p.Admin {
		return nil, apperr.New(apperr.CodeAccessDenied, "only a workspace admin can review set-aside revisions", nil)
	}
	resource := s.resource(resolved.Name)
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
	reviewed, err := s.decrypt(ctx, view.States[d])
	if err != nil {
		return nil, err
	}
	var current map[string]string
	if len(heads) != 0 {
		read, err := s.mergeResource(ctx, resource, view, nil)
		if err != nil {
			return nil, err
		}
		current = read.secrets
	}
	if accept {
		parents := make([]digest.Digest, 0, len(heads)+1)
		for _, head := range heads {
			parents = append(parents, head.Digest)
		}
		if err := s.cps.AcceptStates(resource, view.Graph, view.Compacted.Excuses, append(parents, d), s.head.Digest); err != nil {
			return nil, wspError(err)
		}
	}
	return diffSecrets(current, reviewed), nil
}

package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/merge"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// resourceRead is the current content of one environment: every head storage
// shows, decrypted and merged against their merge base. A key the heads changed
// differently is a conflict and is absent from secrets until a person chooses.
type resourceRead struct {
	view      *wsp.StateView
	heads     []*wsp.VerifiedState
	secrets   map[string]string
	conflicts []merge.Conflict
}

func (r *resourceRead) parents() []digest.Digest {
	out := make([]digest.Digest, len(r.heads))
	for i, h := range r.heads {
		out[i] = h.Digest
	}
	return out
}

// loadResource verifies every revision of env that storage shows and checks it
// against what this device accepted before. It decrypts nothing.
func (s *session) loadResource(ctx context.Context, resource string, also ...digest.Digest) (*wsp.StateView, error) {
	for attempt := 0; ; attempt++ {
		sv, err := wsp.LoadStates(ctx, s.store, s.view, s.workspace, resource, also...)
		if err != nil {
			return nil, wspError(err)
		}
		if sv.Graph.Len() == 0 {
			accepted, err := s.cps.State(resource)
			if err != nil {
				return nil, err
			}
			if len(accepted) > 0 {
				if attempt < acceptedRetries {
					also = append(also, accepted...)
					continue
				}
				return nil, wspError(fmt.Errorf("%w: all previously accepted revisions are missing", wsp.ErrRollback))
			}
			return nil, storageError(storage.ErrNotFound)
		}
		// Load signed deletion records only when something is missing.
		if len(sv.Graph.Missing()) > 0 || s.cps.CheckStates(resource, sv.Graph, nil) != nil {
			records, err := wsp.LoadCompactions(ctx, s.store, s.view, s.workspace, resource)
			if err != nil {
				return nil, wspError(err)
			}
			sv.Compacted = wsp.Compute(records, sv.Graph)
		}
		err = s.cps.CheckStates(resource, sv.Graph, sv.Compacted.Excuses)
		if err == nil {
			return sv, nil
		}
		if !errors.Is(err, wsp.ErrRollback) || attempt == acceptedRetries {
			return nil, wspError(err)
		}
		// Another process of this device may have accepted a revision after
		// the listing above was taken. Fetch the accepted heads by name: one
		// that storage really lost is still missing, and that stays a rollback.
		accepted, err := s.cps.State(resource)
		if err != nil {
			return nil, err
		}
		also = append(append([]digest.Digest(nil), also...), accepted...)
	}
}

// acceptedRetries bounds how often loadResource reads storage again for heads
// that other processes of this device accepted meanwhile.
const acceptedRetries = 2

// decrypt reads the ciphertext of one verified revision, checks it is the one
// the signed State names, and decrypts it. This is the only place a revision's
// blob is transferred, so only revisions whose content is used cost anything.
func (s *session) decrypt(ctx context.Context, st *wsp.VerifiedState) (map[string]string, error) {
	ciphertext, err := wsp.ReadCiphertext(ctx, s.store, st)
	// A signed state exists, so a missing blob is lost data, never an empty
	// environment. Treating it as not-found lets mutations replace its secrets.
	if errors.Is(err, storage.ErrNotFound) {
		return nil, wspError(fmt.Errorf("%w: ciphertext for %s is missing: %w", wsp.ErrRollback, st.Digest, err))
	}
	if err != nil {
		return nil, wspError(err)
	}
	return decryptSecretsObject(ciphertext, s.id)
}

// readResource returns the merged current content of env. The heads must have
// been written by current members, except heads this device already accepted
// (so an admin can take over what a since-removed member last wrote). choices
// settles conflicts a person has already decided. With record set the verified
// view becomes this device's checkpoint.
func (s *session) readResource(ctx context.Context, resource string, choices map[string]merge.Choice, record bool, also ...digest.Digest) (*resourceRead, error) {
	for attempt := 0; ; attempt++ {
		sv, err := s.loadResource(ctx, resource, also...)
		if err != nil {
			return nil, err
		}
		r, err := s.mergeResource(ctx, resource, sv, choices)
		if err != nil || !record {
			return r, err
		}
		err = s.cps.AcceptStates(resource, sv.Graph, sv.Compacted.Excuses, r.parents(), s.head.Digest)
		if err == nil {
			return r, nil
		}
		// Another process of this device accepted a newer head while this one
		// was reading; a fresh read includes it.
		if !errors.Is(err, wsp.ErrRollback) || attempt == acceptedRetries {
			return nil, wspError(err)
		}
	}
}

func (s *session) mergeResource(ctx context.Context, resource string, sv *wsp.StateView, choices map[string]merge.Choice) (*resourceRead, error) {
	accepted, err := s.cps.Accepted(resource)
	if err != nil {
		return nil, err
	}
	heads := s.trustedHeads(sv, accepted)
	if len(heads) == 0 {
		return nil, wspError(fmt.Errorf("%w: no revision of %s was written by a current member", wsp.ErrInvalid, resource))
	}
	r := &resourceRead{view: sv, heads: heads}
	maps := make([]map[string]string, len(r.heads))
	for i, h := range r.heads {
		if maps[i], err = s.decrypt(ctx, h); err != nil {
			return nil, err
		}
	}
	if len(maps) == 1 {
		r.secrets = maps[0]
	} else {
		if missing := sv.MissingParents(); len(missing) > 0 {
			return nil, wspError(fmt.Errorf("%w: revision %s is missing, so the heads cannot be merged yet", wsp.ErrRollback, missing[0]))
		}
		var bases []map[string]string
		for _, b := range sv.Graph.MergeBases(r.parents()) {
			m, err := s.decrypt(ctx, sv.States[b])
			var noMatch *agecrypto.NoIdentityMatchError
			if errors.As(err, &noMatch) {
				// A new member can read current heads without having the key
				// for their pre-join base. Requiring agreement against every
				// head as a possible base preserves all differing values as
				// conflicts; an empty base could silently lose a deletion.
				bases = append(bases, maps...)
				continue
			}
			if err != nil {
				return nil, err
			}
			bases = append(bases, m)
		}
		r.secrets, r.conflicts = merge.Merge(bases, maps, choices)
	}
	return r, nil
}

// trustedHeads picks the heads this device may read as current. A head must be
// written by a current member, or be one this device accepted while its author
// was a member (so an admin can take over what a since-removed member last
// wrote). A head failing both is not an error, because anyone able to write to
// storage can publish one; it is set aside and its parents stand in for it, so
// it neither injects content nor blocks reading.
func (s *session) trustedHeads(sv *wsp.StateView, accepted wsp.StateAcceptance) []*wsp.VerifiedState {
	trusted := func(h *wsp.VerifiedState) bool {
		// A head below a compaction floor was built on removed history: its
		// merge base may be gone, so it cannot be merged.
		if !sv.Compacted.AboveFloors(sv.Graph, h.Digest) {
			return false
		}
		// A returning device cannot carry its old accepted branches across
		// its own removal. A continuously present observer may still take
		// over a revision it accepted before the author's removal.
		return wsp.AuthorIsCurrent(s.view, s.head, h) == nil ||
			slices.Contains(accepted.Heads, h.Digest) && s.view.MembershipUnbroken(s.head.Digest, accepted.Control, s.self())
	}
	var heads []*wsp.VerifiedState
	seen := map[digest.Digest]bool{}
	queue := slices.Clone(sv.Heads)
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		if seen[h.Digest] {
			continue
		}
		seen[h.Digest] = true
		if trusted(h) {
			heads = append(heads, h)
			continue
		}
		for _, p := range h.Parents {
			if parent, ok := sv.States[p]; ok {
				queue = append(queue, parent)
			}
		}
	}
	// A parent that stands in for a set-aside head may already be covered by another head.
	var out []*wsp.VerifiedState
	for _, h := range heads {
		covered := false
		for _, other := range heads {
			if other.Digest != h.Digest && sv.Graph.Ancestors(other.Digest)[h.Digest] {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, h)
		}
	}
	slices.SortFunc(out, func(a, b *wsp.VerifiedState) int { return strings.Compare(string(a.Digest), string(b.Digest)) })
	return out
}

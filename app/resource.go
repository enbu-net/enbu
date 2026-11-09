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
		err = s.cps.CheckState(resource, sv, s.trustedHeads(sv))
		if err == nil && sv.Graph.Len() == 0 {
			return nil, storageError(storage.ErrNotFound)
		}
		if err == nil {
			return sv, nil
		}
		// Another process of this device may have accepted a revision after
		// the listing above was taken; a fresh listing shows it. One that
		// storage really lost is still missing, and that stays a rollback.
		if !errors.Is(err, wsp.ErrRollback) || attempt == acceptedRetries {
			return nil, wspError(err)
		}
	}
}

// acceptedRetries bounds how often loadResource reads storage again for
// revisions that other processes of this device accepted meanwhile.
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
// been written by current members. choices settles conflicts a person has
// already decided. With record set the Generation of the heads read becomes
// this device's checkpoint.
func (s *session) readResource(ctx context.Context, resource string, choices map[string]merge.Choice, record bool, also ...digest.Digest) (*resourceRead, error) {
	for attempt := 0; ; attempt++ {
		sv, err := s.loadResource(ctx, resource, also...)
		if err != nil {
			return nil, err
		}
		r, err := s.mergeResource(ctx, resource, sv, choices)
		if err == nil && record {
			if err = s.cps.AcceptState(resource, sv, r.heads); err != nil {
				err = wspError(err)
			}
		}
		// Storage changed while this read was working: another process of this
		// device accepted a newer revision, or a compaction deleted a revision
		// this read was about to decrypt. A fresh read sees the new view; a
		// revision storage really lost is still missing then.
		if errors.Is(err, wsp.ErrRollback) && attempt < acceptedRetries {
			continue
		}
		if err != nil {
			return nil, err
		}
		return r, nil
	}
}

func (s *session) mergeResource(ctx context.Context, resource string, sv *wsp.StateView, choices map[string]merge.Choice) (*resourceRead, error) {
	heads := s.trustedHeads(sv)
	if len(heads) == 0 {
		return nil, wspError(fmt.Errorf("%w: no revision of %s was written by a current member", wsp.ErrInvalid, resource))
	}
	r := &resourceRead{view: sv, heads: heads}
	maps := make([]map[string]string, len(r.heads))
	for i, h := range r.heads {
		var err error
		if maps[i], err = s.decrypt(ctx, h); err != nil {
			return nil, err
		}
	}
	if len(maps) == 1 {
		r.secrets = maps[0]
	} else {
		var bases []map[string]string
		found := sv.Graph.MergeBases(r.parents())
		if len(found) == 0 && len(sv.Graph.Missing()) > 0 {
			// The heads share no history storage still holds, because old
			// revisions were deleted. Every head counts as a possible base, so
			// any value they disagree on stays a conflict.
			bases = append(bases, maps...)
		}
		for _, b := range found {
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

// trustedHeads picks the heads this device may read as current: written by a
// current member who was not removed since the Control the head names. A head
// failing that is not an error, because anyone able to write to storage can
// publish one; it is set aside and its parents stand in for it, so it neither
// injects content nor blocks reading.
func (s *session) trustedHeads(sv *wsp.StateView) []*wsp.VerifiedState {
	trusted := func(h *wsp.VerifiedState) bool { return wsp.AuthorIsCurrent(s.view, s.head, h) == nil }
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

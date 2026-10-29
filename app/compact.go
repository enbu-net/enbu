package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// CompactResult says what a compaction removed.
type CompactResult struct {
	Kept    int `json:"kept"`    // revisions kept: the latest ones and what they merged
	Removed int `json:"removed"` // revisions deleted from storage
}

// CompactHistory deletes the revisions of env older than the latest keep, so
// storage and the time to read an environment stop growing with its history.
// Only a workspace admin may compact, on a backend that can delete.
//
// The revision keep-1 steps behind the current one (following each revision's
// first parent) becomes the floor: it and every revision descending from it
// stay. Everything else is deleted, after a signed record listing it is
// published, so other devices accept that those revisions are gone instead of
// reporting a rollback. The environment must have one head; concurrent heads
// are merged with sync first.
func (a *App) CompactHistory(ctx context.Context, env string, keep int) (result *CompactResult, err error) {
	defer apperr.NormalizeInto(&err)
	if keep < 1 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "keep at least one revision", nil)
	}
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	s, err := a.openPurgeSession(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	resource := s.resource(resolved.Name)
	read, err := s.readResource(ctx, resource, nil, true)
	if IsNotFoundError(err) {
		return &CompactResult{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := conflictError(read.conflicts); err != nil {
		return nil, err
	}
	if len(read.heads) != 1 {
		return nil, apperr.New(apperr.CodeConflict, "the environment has concurrent changes; run 'enbu sync' to merge them, then compact", nil)
	}
	sv := read.view
	head := read.heads[0].Digest
	floor := compactionFloor(sv, head, keep)
	kept := keptRevisions(sv.Graph, head, floor)
	var removed []digest.Digest
	for d := range sv.States {
		if !kept[d] {
			removed = append(removed, d)
		}
	}
	scope := storage.StateScope(s.workspace, resource)
	// Revisions that failed to verify carry no authority and need no record,
	// but they take space and count against the listing too.
	listed, err := s.store.Discover(ctx, storage.KindState, scope)
	if err != nil {
		return nil, storageError(err)
	}
	var junk []digest.Digest
	for _, d := range listed {
		if _, verified := sv.States[d]; verified || kept[d] {
			continue
		}
		bad, err := s.unverifiable(ctx, resource, scope, d)
		if err != nil {
			return nil, err
		}
		if bad {
			junk = append(junk, d)
		}
	}
	result = &CompactResult{Kept: len(kept)}
	if len(removed)+len(junk) == 0 {
		return result, nil
	}
	// Publish the records before deleting anything: a device must never see a
	// revision it accepted gone without the record that excuses it.
	if err := s.publishCompaction(ctx, resource, floor, removed); err != nil {
		return nil, err
	}
	for _, d := range append(removed, junk...) {
		if err := s.store.Delete(ctx, storage.KindState, scope, d); err != nil && !errorsIsNotFound(err) {
			return result, fmt.Errorf("deleting revision %s after %d deleted: %w", d.Encoded(), result.Removed, storageError(err))
		}
		result.Removed++
	}
	return result, nil
}

// keptRevisions returns the ancestors of head that descend from floor, floor
// and head included.
func keptRevisions(g *wsp.Graph, head, floor digest.Digest) map[digest.Digest]bool {
	anc := g.Ancestors(head)
	children := map[digest.Digest][]digest.Digest{}
	for d := range anc {
		for _, p := range g.Parents(d) {
			if anc[p] {
				children[p] = append(children[p], d)
			}
		}
	}
	kept := map[digest.Digest]bool{floor: true}
	stack := []digest.Digest{floor}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, c := range children[cur] {
			if !kept[c] {
				kept[c] = true
				stack = append(stack, c)
			}
		}
	}
	return kept
}

// unverifiable reports whether a listed revision that the read did not hold is
// one storage serves but that fails verification, so deleting it loses nothing.
// A revision that could not be fetched may only be unreachable for now, and one
// that verifies may have been published after the read or name a Control this
// session does not know yet; both are left alone.
func (s *session) unverifiable(ctx context.Context, resource, scope string, rev digest.Digest) (bool, error) {
	head, err := s.store.FetchHead(ctx, storage.KindState, scope, rev)
	switch {
	case errors.Is(err, storage.ErrNotFound), errors.Is(err, storage.ErrCorrupt):
		return false, nil
	case err != nil:
		return false, storageError(err)
	}
	_, err = wsp.VerifyRevision(s.view, s.workspace, resource, rev, head)
	return err != nil && !errors.Is(err, wsp.ErrRollback), nil
}

// compactionFloor walks keep-1 steps back from head along first parents. A
// history shorter than that ends at its first revision.
func compactionFloor(sv *wsp.StateView, head digest.Digest, keep int) digest.Digest {
	floor := head
	for i := 1; i < keep; i++ {
		next := digest.Digest("")
		for _, p := range sv.Graph.Parents(floor) {
			if sv.Graph.Has(p) {
				next = p
				break
			}
		}
		if next == "" {
			break
		}
		floor = next
	}
	return floor
}

// publishCompaction signs and publishes the records of one compaction, as
// many as the removed list needs.
func (s *session) publishCompaction(ctx context.Context, resource string, floor digest.Digest, removed []digest.Digest) error {
	if len(removed) == 0 {
		return nil
	}
	slices.Sort(removed)
	for start := 0; start < len(removed); start += wsp.MaxCompactionRemoved {
		end := min(start+wsp.MaxCompactionRemoved, len(removed))
		c := wsp.Compaction{Workspace: s.workspace, Resource: resource, Floor: floor, Removed: removed[start:end],
			Control: s.head.Digest, Author: s.self(), CreatedAt: time.Now().Unix()}
		blob, err := wsp.SignCompaction(c, s.signer)
		if err != nil {
			return err
		}
		rev := digest.FromBytes(blob)
		if _, err := wsp.VerifyCompaction(s.view, s.workspace, resource, rev, blob); err != nil {
			return err
		}
		obj := storage.Object{Kind: storage.KindCompaction, Scope: c.Scope(), Rev: rev, Head: blob}
		if err := s.store.Publish(ctx, obj); err != nil {
			return fmt.Errorf("saving the compaction record: %w", storageError(err))
		}
	}
	return nil
}

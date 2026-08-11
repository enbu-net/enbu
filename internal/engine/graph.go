package engine

import (
	"context"
	"fmt"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const MaxGraphRevisions = 100_000

// Graph is an authenticated, exact strong closure. Logical edges remain in
// each Revision but are never followed while opening the closure.
type Graph struct {
	Root       artifact.SealedRef
	ByUID      map[artifact.UUID]OpenedRevision
	ByRevision map[digest.Digest]OpenedRevision
}

// OpenGraph follows only pinned references, decrypts every independently
// granted object, and validates the complete closure before exposing it.
func OpenGraph(
	ctx context.Context,
	source artifact.ObjectSource,
	device *artifact.DeviceIdentity,
	verifier artifact.EnrollmentVerifier,
	root artifact.SealedRef,
) (Graph, error) {
	if err := root.Validate(); err != nil {
		return Graph{}, err
	}
	pending := []artifact.SealedRef{root}
	queued := map[digest.Digest]artifact.SealedRef{root.Revision: root}
	byRevision := make(map[digest.Digest]OpenedRevision)
	records := make([]artifact.RevisionRecord, 0, 16)

	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return Graph{}, err
		}
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		delete(queued, current.Revision)
		if existing, ok := byRevision[current.Revision]; ok {
			if existing.Ref != current {
				return Graph{}, fmt.Errorf("%w: one revision has conflicting material or grant", artifact.ErrPinnedTargetMismatch)
			}
			continue
		}
		opened, err := OpenRevision(ctx, source, device, verifier, current)
		if err != nil {
			return Graph{}, fmt.Errorf("open revision %s: %w", current.Revision, err)
		}
		byRevision[current.Revision] = opened
		records = append(records, artifact.RevisionRecord{Ref: current, Value: opened.Revision})
		for _, edge := range opened.Revision.Edges {
			if edge.Strength == artifact.EdgePinned {
				if err := enqueuePinned(&pending, queued, byRevision, *edge.Pinned); err != nil {
					return Graph{}, err
				}
			}
		}
	}
	if err := artifact.ValidateStrongClosure(root, records); err != nil {
		return Graph{}, err
	}
	byUID := make(map[artifact.UUID]OpenedRevision, len(byRevision))
	for _, opened := range byRevision {
		byUID[opened.Revision.UID] = opened
	}
	return Graph{Root: root, ByUID: byUID, ByRevision: byRevision}, nil
}

// enqueuePinned keeps the traversal frontier unique by revision. Without this
// queued set, a valid graph with many distinct edges to one target could grow
// pending memory with every edge even though the target is opened only once.
func enqueuePinned(
	pending *[]artifact.SealedRef,
	queued map[digest.Digest]artifact.SealedRef,
	opened map[digest.Digest]OpenedRevision,
	next artifact.SealedRef,
) error {
	if existing, ok := opened[next.Revision]; ok {
		if existing.Ref != next {
			return fmt.Errorf("%w: one revision has conflicting material or grant", artifact.ErrPinnedTargetMismatch)
		}
		return nil
	}
	if existing, ok := queued[next.Revision]; ok {
		if existing != next {
			return fmt.Errorf("%w: one queued revision has conflicting material or grant", artifact.ErrPinnedTargetMismatch)
		}
		return nil
	}
	if len(opened)+len(queued) >= MaxGraphRevisions {
		return fmt.Errorf("engine: strong closure exceeds %d revisions", MaxGraphRevisions)
	}
	queued[next.Revision] = next
	*pending = append(*pending, next)
	return nil
}

// Closure returns every encrypted object needed to retain this graph. The
// registry layer canonicalizes and deduplicates descriptors before upload.
func (graph Graph) Closure() Closure {
	var closure Closure
	for _, opened := range graph.ByRevision {
		closure.Materials = append(closure.Materials, opened.MaterialDescriptor)
		closure.Grants = append(closure.Grants, opened.GrantDescriptor)
		closure.Chunks = appendStreamDescriptors(closure.Chunks, opened.Manifest.Revision)
		for _, payload := range opened.Manifest.Payloads {
			closure.Chunks = appendStreamDescriptors(closure.Chunks, payload.Stream)
		}
	}
	return closure
}

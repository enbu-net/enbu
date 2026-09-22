package artifact

import (
	"errors"
	"fmt"

	"github.com/opencontainers/go-digest"
)

var (
	ErrDuplicateRevision     = errors.New("duplicate revision in closure")
	ErrConflictingUID        = errors.New("multiple revisions for one UID in closure")
	ErrStrongCycle           = errors.New("pinned edge cycle")
	ErrMissingPinnedRevision = errors.New("missing pinned revision")
	ErrPinnedTargetMismatch  = errors.New("pinned edge target mismatch")
	ErrUnreachableRevision   = errors.New("revision outside strong closure")
)

// RevisionRecord associates decoded revision content with the material and
// grant that seal it. Ref.Revision must equal CanonicalDigest(Value).
type RevisionRecord struct {
	Ref   SealedRef `cbor:"ref" json:"ref"`
	Value Revision  `cbor:"value" json:"value"`
}

type validatedGraph struct {
	byDigest map[digest.Digest]RevisionRecord
}

// ValidateStrongDAG validates all records as a pinned-edge DAG. Logical edges
// are deliberately excluded from traversal and therefore may form cycles or
// refer to UIDs that are not present in records.
func ValidateStrongDAG(records []RevisionRecord) error {
	_, err := indexAndValidate(records)
	return err
}

// ValidateStrongClosure validates that records are exactly the pinned-edge
// closure rooted at root. Duplicate revision records and multiple revisions for
// one UID are rejected even when their decoded content would otherwise match.
func ValidateStrongClosure(root SealedRef, records []RevisionRecord) error {
	if err := root.Validate(); err != nil {
		return fmt.Errorf("root sealed reference: %w", err)
	}
	graph, err := indexAndValidate(records)
	if err != nil {
		return err
	}
	rootRecord, ok := graph.byDigest[root.Revision]
	if !ok {
		return fmt.Errorf("%w: root %s", ErrMissingPinnedRevision, root.Revision)
	}
	if rootRecord.Ref != root {
		return fmt.Errorf("%w: root sealed reference does not match record", ErrPinnedTargetMismatch)
	}

	reachable := make(map[digest.Digest]struct{}, len(records))
	pending := []digest.Digest{root.Revision}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, seen := reachable[current]; seen {
			continue
		}
		reachable[current] = struct{}{}
		for _, edge := range graph.byDigest[current].Value.Edges {
			if edge.Strength == EdgePinned {
				pending = append(pending, edge.Pinned.Revision)
			}
		}
	}
	if len(reachable) != len(records) {
		for revision := range graph.byDigest {
			if _, ok := reachable[revision]; !ok {
				return fmt.Errorf("%w: %s", ErrUnreachableRevision, revision)
			}
		}
	}
	return nil
}

func indexAndValidate(records []RevisionRecord) (validatedGraph, error) {
	graph := validatedGraph{byDigest: make(map[digest.Digest]RevisionRecord, len(records))}
	byUID := make(map[UUID]digest.Digest, len(records))
	for i, record := range records {
		if err := record.Ref.Validate(); err != nil {
			return validatedGraph{}, fmt.Errorf("records[%d] reference: %w", i, err)
		}
		if err := record.Value.Validate(); err != nil {
			return validatedGraph{}, fmt.Errorf("records[%d] value: %w", i, err)
		}
		actual, err := CanonicalDigest(record.Value)
		if err != nil {
			return validatedGraph{}, fmt.Errorf("records[%d] digest: %w", i, err)
		}
		if actual != record.Ref.Revision {
			return validatedGraph{}, fmt.Errorf("%w: records[%d] declares %s, calculated %s", ErrPinnedTargetMismatch, i, record.Ref.Revision, actual)
		}
		if _, exists := graph.byDigest[record.Ref.Revision]; exists {
			return validatedGraph{}, fmt.Errorf("%w: %s", ErrDuplicateRevision, record.Ref.Revision)
		}
		if previous, exists := byUID[record.Value.UID]; exists {
			return validatedGraph{}, fmt.Errorf("%w: UID %s resolves to %s and %s", ErrConflictingUID, record.Value.UID, previous, record.Ref.Revision)
		}
		graph.byDigest[record.Ref.Revision] = record
		byUID[record.Value.UID] = record.Ref.Revision
	}

	for revision, record := range graph.byDigest {
		for _, edge := range record.Value.Edges {
			if edge.Strength != EdgePinned {
				continue
			}
			target, ok := graph.byDigest[edge.Pinned.Revision]
			if !ok {
				return validatedGraph{}, fmt.Errorf("%w: %s edge %s pins %s", ErrMissingPinnedRevision, revision, edge.ID, edge.Pinned.Revision)
			}
			if target.Ref != *edge.Pinned || target.Value.UID != edge.Target {
				return validatedGraph{}, fmt.Errorf("%w: %s edge %s", ErrPinnedTargetMismatch, revision, edge.ID)
			}
		}
	}

	if err := validateNoStrongCycles(graph); err != nil {
		return validatedGraph{}, err
	}
	return graph, nil
}

func validateNoStrongCycles(graph validatedGraph) error {
	const (
		unvisited uint8 = iota
		visiting
		visited
	)
	colors := make(map[digest.Digest]uint8, len(graph.byDigest))
	type frame struct {
		revision digest.Digest
		nextEdge int
	}

	for revision := range graph.byDigest {
		if colors[revision] != unvisited {
			continue
		}
		colors[revision] = visiting
		stack := []frame{{revision: revision}}
		for len(stack) > 0 {
			current := &stack[len(stack)-1]
			edges := graph.byDigest[current.revision].Value.Edges
			for current.nextEdge < len(edges) && edges[current.nextEdge].Strength != EdgePinned {
				current.nextEdge++
			}
			if current.nextEdge == len(edges) {
				colors[current.revision] = visited
				stack = stack[:len(stack)-1]
				continue
			}

			target := edges[current.nextEdge].Pinned.Revision
			current.nextEdge++
			switch colors[target] {
			case visiting:
				return fmt.Errorf("%w: %s", ErrStrongCycle, target)
			case unvisited:
				colors[target] = visiting
				stack = append(stack, frame{revision: target})
			}
		}
	}
	return nil
}

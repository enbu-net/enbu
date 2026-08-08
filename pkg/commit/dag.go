package commit

import (
	"context"
	"fmt"
	"sort"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	MaxDAGCommits = 10_000
	MaxDAGBytes   = 256 * 1024 * 1024
)

// DAG is a complete, authenticated commit history. It retains every frontier
// member; no mutable or last-writer-wins head exists in this model.
type DAG struct {
	workspace artifact.UUID
	commits   map[digest.Digest]VerifiedCommit
	parents   map[digest.Digest][]digest.Digest
	children  map[digest.Digest][]digest.Digest
	root      digest.Digest
}

// BuildDAG verifies canonical plaintext digests, signatures, historical key
// bindings, parent completeness, workspace consistency, operation uniqueness,
// a single initialization root, and acyclicity.
func BuildDAG(ctx context.Context, objects map[digest.Digest][]byte, verifier artifact.EnrollmentVerifier) (*DAG, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(objects) == 0 || len(objects) > MaxDAGCommits {
		return nil, fmt.Errorf("%w: history must contain 1-%d commits", ErrInvalidCommitDAG, MaxDAGCommits)
	}
	digests := make([]digest.Digest, 0, len(objects))
	totalBytes := 0
	for objectDigest, encoded := range objects {
		if err := validateDigest(objectDigest); err != nil {
			return nil, fmt.Errorf("%w: object digest: %v", ErrInvalidCommitDAG, err)
		}
		if len(encoded) == 0 || len(encoded) > MaxCommitBytes || len(encoded) > MaxDAGBytes-totalBytes {
			return nil, fmt.Errorf("%w: history exceeds commit or aggregate byte limit", ErrInvalidCommitDAG)
		}
		totalBytes += len(encoded)
		digests = append(digests, objectDigest)
	}
	sortDigests(digests)

	verifiedCommits := make([]VerifiedCommit, 0, len(objects))
	for _, objectDigest := range digests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		verified, err := VerifySignedCommit(ctx, objects[objectDigest], verifier)
		if err != nil {
			return nil, fmt.Errorf("%w: verify %s: %w", ErrInvalidCommitDAG, objectDigest, err)
		}
		if verified.Digest() != objectDigest {
			return nil, fmt.Errorf("%w: %w: key %s, plaintext %s", ErrInvalidCommitDAG, ErrCommitDigestMismatch, objectDigest, verified.Digest())
		}
		verifiedCommits = append(verifiedCommits, verified)
	}
	return BuildVerifiedDAG(ctx, verifiedCommits)
}

// BuildVerifiedDAG constructs a complete history from already authenticated
// type-state values, avoiding a second download, decrypt, or enrollment check
// after registry discovery.
func BuildVerifiedDAG(ctx context.Context, commits []VerifiedCommit) (*DAG, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(commits) == 0 || len(commits) > MaxDAGCommits {
		return nil, fmt.Errorf("%w: history must contain 1-%d commits", ErrInvalidCommitDAG, MaxDAGCommits)
	}
	dag := &DAG{
		commits:  make(map[digest.Digest]VerifiedCommit, len(commits)),
		parents:  make(map[digest.Digest][]digest.Digest, len(commits)),
		children: make(map[digest.Digest][]digest.Digest, len(commits)),
	}
	operations := make(map[artifact.UUID]digest.Digest, len(commits))
	totalBytes := 0
	for _, verified := range commits {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		objectDigest := verified.Digest()
		if err := validateDigest(objectDigest); err != nil || verified.encodedSize <= 0 ||
			verified.encodedSize > MaxCommitBytes || verified.encodedSize > MaxDAGBytes-totalBytes {
			return nil, fmt.Errorf("%w: invalid verified Commit identity or byte budget", ErrInvalidCommitDAG)
		}
		if _, exists := dag.commits[objectDigest]; exists {
			continue
		}
		totalBytes += verified.encodedSize
		value := verified.Commit()
		if dag.workspace == "" {
			dag.workspace = value.WorkspaceID
		} else if value.WorkspaceID != dag.workspace {
			return nil, fmt.Errorf("%w: commit %s belongs to workspace %s, want %s", ErrInvalidCommitDAG, objectDigest, value.WorkspaceID, dag.workspace)
		}
		if previous, exists := operations[value.OperationID]; exists {
			return nil, fmt.Errorf("%w: operation ID %s appears in %s and %s", ErrInvalidCommitDAG, value.OperationID, previous, objectDigest)
		}
		operations[value.OperationID] = objectDigest
		dag.commits[objectDigest] = verified
		dag.parents[objectDigest] = append([]digest.Digest(nil), value.Parents...)
	}

	digests := make([]digest.Digest, 0, len(dag.commits))
	for objectDigest := range dag.commits {
		digests = append(digests, objectDigest)
	}
	sortDigests(digests)
	roots := make([]digest.Digest, 0, 1)
	for _, child := range digests {
		parents := dag.parents[child]
		if len(parents) == 0 {
			roots = append(roots, child)
		}
		for _, parent := range parents {
			if _, exists := dag.commits[parent]; !exists {
				return nil, fmt.Errorf("%w: commit %s has missing parent %s", ErrInvalidCommitDAG, child, parent)
			}
			dag.children[parent] = append(dag.children[parent], child)
		}
	}
	if len(roots) != 1 {
		return nil, fmt.Errorf("%w: history has %d initialization roots", ErrInvalidCommitDAG, len(roots))
	}
	dag.root = roots[0]
	for objectDigest := range dag.children {
		sortDigests(dag.children[objectDigest])
	}
	if err := validateAcyclic(dag.parents, dag.children); err != nil {
		return nil, err
	}
	return dag, nil
}

func validateAcyclic(parents, children map[digest.Digest][]digest.Digest) error {
	remainingParents := make(map[digest.Digest]int, len(parents))
	ready := make([]digest.Digest, 0, len(parents))
	for objectDigest, objectParents := range parents {
		remainingParents[objectDigest] = len(objectParents)
		if len(objectParents) == 0 {
			ready = append(ready, objectDigest)
		}
	}
	processed := 0
	for len(ready) > 0 {
		current := ready[len(ready)-1]
		ready = ready[:len(ready)-1]
		processed++
		for _, child := range children[current] {
			remainingParents[child]--
			if remainingParents[child] == 0 {
				ready = append(ready, child)
			}
		}
	}
	if processed != len(parents) {
		return fmt.Errorf("%w: commit parent cycle", ErrInvalidCommitDAG)
	}
	return nil
}

// WorkspaceID returns the immutable workspace ID shared by the history.
func (d *DAG) WorkspaceID() artifact.UUID {
	if d == nil {
		return ""
	}
	return d.workspace
}

// Root returns the unique initialization Commit digest.
func (d *DAG) Root() digest.Digest {
	if d == nil {
		return ""
	}
	return d.root
}

func (d *DAG) Len() int {
	if d == nil {
		return 0
	}
	return len(d.commits)
}

// Commit returns a defensive copy of one verified Commit.
func (d *DAG) Commit(objectDigest digest.Digest) (Commit, bool) {
	if d == nil {
		return Commit{}, false
	}
	verified, exists := d.commits[objectDigest]
	if !exists {
		return Commit{}, false
	}
	return verified.Commit(), true
}

// Frontier returns every commit not reachable as an ancestor of another
// discovered commit. Results are sorted by canonical digest text.
func (d *DAG) Frontier() []digest.Digest {
	if d == nil {
		return nil
	}
	frontier := make([]digest.Digest, 0)
	for objectDigest := range d.commits {
		if len(d.children[objectDigest]) == 0 {
			frontier = append(frontier, objectDigest)
		}
	}
	sortDigests(frontier)
	return frontier
}

// Reachable reports whether target can be reached from start by following
// zero or more parent links. A commit is therefore reachable from itself.
func (d *DAG) Reachable(start, target digest.Digest) (bool, error) {
	if d == nil {
		return false, fmt.Errorf("%w: nil DAG", ErrInvalidCommitDAG)
	}
	if _, exists := d.commits[start]; !exists {
		return false, fmt.Errorf("%w: %s", ErrCommitNotFound, start)
	}
	if _, exists := d.commits[target]; !exists {
		return false, fmt.Errorf("%w: %s", ErrCommitNotFound, target)
	}
	return d.reachable(start, target), nil
}

func (d *DAG) reachable(start, target digest.Digest) bool {
	stack := []digest.Digest{start}
	seen := make(map[digest.Digest]struct{})
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current == target {
			return true
		}
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		stack = append(stack, d.parents[current]...)
	}
	return false
}

// ReachableFrom returns start and all of its ancestors, deterministically
// sorted by canonical digest text.
func (d *DAG) ReachableFrom(start digest.Digest) ([]digest.Digest, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: nil DAG", ErrInvalidCommitDAG)
	}
	if _, exists := d.commits[start]; !exists {
		return nil, fmt.Errorf("%w: %s", ErrCommitNotFound, start)
	}
	stack := []digest.Digest{start}
	seen := make(map[digest.Digest]struct{})
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, exists := seen[current]; exists {
			continue
		}
		seen[current] = struct{}{}
		stack = append(stack, d.parents[current]...)
	}
	result := make([]digest.Digest, 0, len(seen))
	for objectDigest := range seen {
		result = append(result, objectDigest)
	}
	sortDigests(result)
	return result, nil
}

// MergeBases returns every best common ancestor. Criss-cross histories may
// have multiple merge bases; they are retained and deterministically sorted.
func (d *DAG) MergeBases(left, right digest.Digest) ([]digest.Digest, error) {
	leftAncestors, err := d.ancestorSet(left)
	if err != nil {
		return nil, err
	}
	rightAncestors, err := d.ancestorSet(right)
	if err != nil {
		return nil, err
	}
	common := make(map[digest.Digest]struct{})
	for candidate := range leftAncestors {
		if _, exists := rightAncestors[candidate]; exists {
			common[candidate] = struct{}{}
		}
	}
	bases := make([]digest.Digest, 0, len(common))
	for candidate := range common {
		best := true
		// If an immediate child is common, candidate is an ancestor of a
		// strictly better common ancestor. Every intermediate child on a path
		// to a common descendant is itself common, so one level is sufficient.
		for _, child := range d.children[candidate] {
			if _, exists := common[child]; exists {
				best = false
				break
			}
		}
		if best {
			bases = append(bases, candidate)
		}
	}
	sortDigests(bases)
	return bases, nil
}

func (d *DAG) ancestorSet(start digest.Digest) (map[digest.Digest]struct{}, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: nil DAG", ErrInvalidCommitDAG)
	}
	if _, exists := d.commits[start]; !exists {
		return nil, fmt.Errorf("%w: %s", ErrCommitNotFound, start)
	}
	result := make(map[digest.Digest]struct{})
	stack := []digest.Digest{start}
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, exists := result[current]; exists {
			continue
		}
		result[current] = struct{}{}
		stack = append(stack, d.parents[current]...)
	}
	return result, nil
}

func sortDigests(values []digest.Digest) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].String() < values[j].String()
	})
}

package apphost

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/opencontainers/go-digest"
)

// Snapshot returns the complete accessible logical history and the union of
// resources visible from its pinned frontier. Payload streams are never
// opened: OpenGraph decrypts only authenticated revision metadata.
func (executor *Executor) Snapshot(ctx context.Context, execution host.QueryExecution) (host.SnapshotData, error) {
	state, err := executor.lookupQuery(ctx, execution)
	if err != nil {
		return host.SnapshotData{}, err
	}
	dag, err := executor.queryDAG(ctx, state)
	if err != nil {
		return host.SnapshotData{}, err
	}
	if dag == nil {
		return host.SnapshotData{}, nil
	}

	frontier := dag.Frontier()
	resources := make(map[artifact.UUID]struct{})
	for _, commitID := range frontier {
		value, ok := dag.Commit(commitID)
		if !ok {
			return host.SnapshotData{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, commitID)
		}
		graph, openErr := executor.openQueryGraph(ctx, state, value.Root)
		if openErr != nil {
			return host.SnapshotData{}, openErr
		}
		for uid := range graph.ByUID {
			resources[uid] = struct{}{}
		}
	}
	return host.SnapshotData{
		Frontier:      append([]digest.Digest(nil), frontier...),
		ResourceCount: uint64(len(resources)),
		CommitCount:   uint64(dag.Len()),
	}, nil
}

// ListResources lists authenticated metadata from exactly one pinned Commit.
// A newer remote frontier does not change the selected graph.
func (executor *Executor) ListResources(
	ctx context.Context,
	execution host.QueryExecution,
	query host.ResourcePageQuery,
) (host.ResourcePageData, error) {
	state, err := executor.lookupQuery(ctx, execution)
	if err != nil {
		return host.ResourcePageData{}, err
	}
	if err := validateQueryPage(query.Offset, query.Limit); err != nil {
		return host.ResourcePageData{}, err
	}
	dag, err := executor.queryDAG(ctx, state)
	if err != nil {
		return host.ResourcePageData{}, err
	}
	value, err := pinnedCommit(dag, query.AtCommit)
	if err != nil {
		return host.ResourcePageData{}, err
	}
	graph, err := executor.openQueryGraph(ctx, state, value.Root)
	if err != nil {
		return host.ResourcePageData{}, err
	}

	resources := make([]host.ResourceMetadata, 0, len(graph.ByUID))
	for _, opened := range graph.ByUID {
		resources = append(resources, cloneQueryResource(opened))
	}
	sort.Slice(resources, func(left, right int) bool {
		return resources[left].UID < resources[right].UID
	})
	start, end, more, next, err := queryPage(len(resources), query.Offset, query.Limit)
	if err != nil {
		return host.ResourcePageData{}, err
	}
	return host.ResourcePageData{
		Resources:  cloneQueryResources(resources[start:end]),
		More:       more,
		NextOffset: next,
	}, nil
}

// ListCommits returns the exact history closed over the supplied frontier.
// Stale but valid frontier pins remain usable so cursor pagination cannot be
// invalidated by a concurrent publication.
func (executor *Executor) ListCommits(
	ctx context.Context,
	execution host.QueryExecution,
	query host.CommitPageQuery,
) (host.CommitPageData, error) {
	state, err := executor.lookupQuery(ctx, execution)
	if err != nil {
		return host.CommitPageData{}, err
	}
	if err := validateQueryPage(query.Offset, query.Limit); err != nil {
		return host.CommitPageData{}, err
	}
	dag, err := executor.queryDAG(ctx, state)
	if err != nil {
		return host.CommitPageData{}, err
	}
	frontier, err := validatePinnedFrontier(dag, query.Frontier)
	if err != nil {
		return host.CommitPageData{}, err
	}

	seen := make(map[digest.Digest]struct{})
	for _, head := range frontier {
		reachable, reachableErr := dag.ReachableFrom(head)
		if reachableErr != nil {
			return host.CommitPageData{}, reachableErr
		}
		for _, commitID := range reachable {
			seen[commitID] = struct{}{}
		}
	}
	ids := make([]digest.Digest, 0, len(seen))
	for commitID := range seen {
		ids = append(ids, commitID)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })

	commits := make([]host.CommitMetadata, 0, len(ids))
	for _, commitID := range ids {
		value, ok := dag.Commit(commitID)
		if !ok {
			return host.CommitPageData{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, commitID)
		}
		commits = append(commits, cloneQueryCommit(commitID, value))
	}
	start, end, more, next, err := queryPage(len(commits), query.Offset, query.Limit)
	if err != nil {
		return host.CommitPageData{}, err
	}
	return host.CommitPageData{
		Commits:    cloneQueryCommits(commits[start:end]),
		More:       more,
		NextOffset: next,
	}, nil
}

// GetResource returns metadata for one UID from exactly one pinned Commit.
func (executor *Executor) GetResource(
	ctx context.Context,
	execution host.QueryExecution,
	query host.ResourceQuery,
) (host.ResourceMetadata, error) {
	if err := query.UID.Validate(); err != nil {
		return host.ResourceMetadata{}, host.ErrInvalidQuery
	}
	state, err := executor.lookupQuery(ctx, execution)
	if err != nil {
		return host.ResourceMetadata{}, err
	}
	dag, err := executor.queryDAG(ctx, state)
	if err != nil {
		return host.ResourceMetadata{}, err
	}
	value, err := pinnedCommit(dag, query.AtCommit)
	if err != nil {
		return host.ResourceMetadata{}, err
	}
	graph, err := executor.openQueryGraph(ctx, state, value.Root)
	if err != nil {
		return host.ResourceMetadata{}, err
	}
	opened, exists := graph.ByUID[query.UID]
	if !exists {
		return host.ResourceMetadata{}, host.ErrResourceNotFound
	}
	return cloneQueryResource(opened), nil
}

func (executor *Executor) lookupQuery(ctx context.Context, execution host.QueryExecution) (*workspaceState, error) {
	if ctx == nil {
		return nil, errors.New("apphost: nil query context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if execution == nil {
		return nil, errors.New("apphost: nil query execution")
	}
	workspaceID := execution.WorkspaceID()
	if err := workspaceID.Validate(); err != nil {
		return nil, ErrStateConflict
	}
	executor.mu.RLock()
	state := executor.states[workspaceID]
	executor.mu.RUnlock()
	if state == nil || state.config.Workspace != workspaceID || state.root != execution.Root() || state.revision != execution.ConfigRevision() {
		return nil, ErrStateConflict
	}
	return state, nil
}

func (executor *Executor) queryDAG(ctx context.Context, state *workspaceState) (*commitmodel.DAG, error) {
	return executor.completeDAG(ctx, state)
}

func (executor *Executor) openQueryGraph(ctx context.Context, state *workspaceState, root artifact.SealedRef) (engine.Graph, error) {
	return engine.OpenGraph(
		ctx,
		fallbackSource{local: state.objects, remote: state.remote},
		state.device,
		state.verifier,
		root,
	)
}

func pinnedCommit(dag *commitmodel.DAG, id digest.Digest) (commitmodel.Commit, error) {
	if err := id.Validate(); err != nil || id.Algorithm() != digest.SHA256 {
		return commitmodel.Commit{}, host.ErrInvalidQuery
	}
	if dag == nil {
		return commitmodel.Commit{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, id)
	}
	value, exists := dag.Commit(id)
	if !exists {
		return commitmodel.Commit{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, id)
	}
	return value, nil
}

func validatePinnedFrontier(dag *commitmodel.DAG, values []digest.Digest) ([]digest.Digest, error) {
	if dag == nil || len(values) == 0 || len(values) > host.MaxQueryFrontier {
		return nil, host.ErrInvalidQuery
	}
	frontier := append([]digest.Digest(nil), values...)
	sort.Slice(frontier, func(left, right int) bool { return frontier[left] < frontier[right] })
	for index, value := range frontier {
		if err := value.Validate(); err != nil || value.Algorithm() != digest.SHA256 {
			return nil, host.ErrInvalidQuery
		}
		if index > 0 && frontier[index-1] == value {
			return nil, host.ErrInvalidQuery
		}
		if _, exists := dag.Commit(value); !exists {
			return nil, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, value)
		}
	}
	// A frontier is an antichain. Accepting an ancestor beside its descendant
	// would make the pin ambiguous and masks malformed client state.
	for left := 0; left < len(frontier); left++ {
		for right := left + 1; right < len(frontier); right++ {
			leftFromRight, err := dag.Reachable(frontier[left], frontier[right])
			if err != nil {
				return nil, err
			}
			rightFromLeft, err := dag.Reachable(frontier[right], frontier[left])
			if err != nil {
				return nil, err
			}
			if leftFromRight || rightFromLeft {
				return nil, host.ErrInvalidQuery
			}
		}
	}
	return frontier, nil
}

func validateQueryPage(offset uint64, limit uint32) error {
	if limit == 0 || limit > host.MaxQueryPageSize {
		return host.ErrInvalidQuery
	}
	// Keep offset in the int domain used for bounded in-memory result slices.
	maxInt := int(^uint(0) >> 1)
	if offset > uint64(maxInt) {
		return host.ErrInvalidQuery
	}
	return nil
}

func queryPage(total int, offset uint64, limit uint32) (start, end int, more bool, next uint64, err error) {
	if err := validateQueryPage(offset, limit); err != nil {
		return 0, 0, false, 0, err
	}
	if offset > uint64(total) {
		return 0, 0, false, 0, host.ErrInvalidQuery
	}
	start = int(offset)
	if int(limit) >= total-start {
		end = total
	} else {
		end = start + int(limit)
	}
	more = end < total
	if more {
		next = uint64(end)
	}
	return start, end, more, next, nil
}

func cloneQueryResource(opened engine.OpenedRevision) host.ResourceMetadata {
	return host.ResourceMetadata{
		Kind:   opened.Revision.Kind,
		UID:    opened.Revision.UID,
		Schema: opened.Revision.Schema,
		Metadata: artifact.Metadata{
			Name:        opened.Revision.Metadata.Name,
			Labels:      cloneQueryStrings(opened.Revision.Metadata.Labels),
			Annotations: cloneQueryStrings(opened.Revision.Metadata.Annotations),
		},
		Sealed: opened.Ref,
	}
}

func cloneQueryResources(values []host.ResourceMetadata) []host.ResourceMetadata {
	cloned := make([]host.ResourceMetadata, len(values))
	for index, value := range values {
		cloned[index] = value
		cloned[index].Metadata.Labels = cloneQueryStrings(value.Metadata.Labels)
		cloned[index].Metadata.Annotations = cloneQueryStrings(value.Metadata.Annotations)
	}
	return cloned
}

func cloneQueryCommit(id digest.Digest, value commitmodel.Commit) host.CommitMetadata {
	return host.CommitMetadata{
		ID:          id,
		Root:        value.Root,
		Policy:      value.Policy,
		Parents:     append([]digest.Digest(nil), value.Parents...),
		Actor:       value.Actor,
		DeviceID:    value.DeviceID,
		OperationID: value.OperationID,
		Timestamp:   value.Timestamp,
	}
}

func cloneQueryCommits(values []host.CommitMetadata) []host.CommitMetadata {
	cloned := make([]host.CommitMetadata, len(values))
	for index, value := range values {
		cloned[index] = value
		cloned[index].Parents = append([]digest.Digest(nil), value.Parents...)
	}
	return cloned
}

func cloneQueryStrings(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

var _ host.QueryExecutor = (*Executor)(nil)

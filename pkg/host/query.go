package host

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/opencontainers/go-digest"
	"golang.org/x/text/unicode/norm"
)

const (
	DefaultQueryPageSize uint32 = 50
	MaxQueryPageSize     uint32 = 200
	MaxQueryFrontier            = 64
)

var (
	ErrInvalidQuery       = errors.New("host: invalid query")
	ErrInvalidQueryResult = errors.New("host: invalid query result")
	ErrInvalidQueryCursor = errors.New("host: invalid query cursor")
	ErrQueryCursorExpired = errors.New("host: query cursor expired")
	ErrQueryCursorLimit   = errors.New("host: query cursor limit reached")
	ErrResourceNotFound   = errors.New("host: resource not found")
)

type QueryCursor string

func (cursor QueryCursor) validate() error {
	_, err := artifact.ParseUUID(string(cursor))
	return err
}

// QueryExecution exposes immutable workspace identity only to the trusted
// process-wide QueryExecutor. It cannot open secret input or output handles.
type QueryExecution interface {
	WorkspaceID() artifact.UUID
	Root() string
	ConfigRevision() digest.Digest
}

// QueryExecutor is the closed read-only backend boundary. Pagination offsets
// never cross the client boundary; the host wraps them in random, session-bound
// cursor capabilities.
type QueryExecutor interface {
	Snapshot(context.Context, QueryExecution) (SnapshotData, error)
	ListResources(context.Context, QueryExecution, ResourcePageQuery) (ResourcePageData, error)
	ListCommits(context.Context, QueryExecution, CommitPageQuery) (CommitPageData, error)
	GetResource(context.Context, QueryExecution, ResourceQuery) (ResourceMetadata, error)
}

type SnapshotData struct {
	Frontier      []digest.Digest
	ResourceCount uint64
	CommitCount   uint64
}

type WorkspaceSnapshot struct {
	Frontier       []digest.Digest `json:"frontier"`
	ConfigRevision digest.Digest   `json:"config_revision"`
	ResourceCount  uint64          `json:"resource_count"`
	CommitCount    uint64          `json:"commit_count"`
}

type ResourceMetadata struct {
	Kind     artifact.Kind      `json:"kind"`
	UID      artifact.UUID      `json:"uid"`
	Schema   artifact.TypeRef   `json:"schema"`
	Metadata artifact.Metadata  `json:"metadata"`
	Sealed   artifact.SealedRef `json:"sealed"`
}

type CommitMetadata struct {
	ID          digest.Digest         `json:"id"`
	Root        artifact.SealedRef    `json:"root"`
	Policy      artifact.SealedRef    `json:"policy"`
	Parents     []digest.Digest       `json:"parents,omitempty"`
	Actor       string                `json:"actor"`
	DeviceID    artifact.UUID         `json:"device_id"`
	OperationID artifact.UUID         `json:"operation_id"`
	Timestamp   commitmodel.Timestamp `json:"timestamp"`
}

type ListResourcesRequest struct {
	AtCommit digest.Digest `json:"at_commit"`
	PageSize uint32        `json:"page_size,omitempty"`
	Cursor   QueryCursor   `json:"cursor,omitempty"`
}

type ResourcePageQuery struct {
	AtCommit digest.Digest
	Offset   uint64
	Limit    uint32
}

type ResourcePageData struct {
	Resources  []ResourceMetadata
	More       bool
	NextOffset uint64
}

type ResourcePage struct {
	Resources []ResourceMetadata `json:"resources"`
	Next      QueryCursor        `json:"next,omitempty"`
}

type ListCommitsRequest struct {
	Frontier []digest.Digest `json:"frontier"`
	PageSize uint32          `json:"page_size,omitempty"`
	Cursor   QueryCursor     `json:"cursor,omitempty"`
}

type CommitPageQuery struct {
	Frontier []digest.Digest
	Offset   uint64
	Limit    uint32
}

type CommitPageData struct {
	Commits    []CommitMetadata
	More       bool
	NextOffset uint64
}

type CommitPage struct {
	Commits []CommitMetadata `json:"commits"`
	Next    QueryCursor      `json:"next,omitempty"`
}

type GetResourceRequest struct {
	AtCommit digest.Digest `json:"at_commit"`
	UID      artifact.UUID `json:"uid"`
}

type ResourceQuery struct {
	AtCommit digest.Digest
	UID      artifact.UUID
}

type queryKind uint8

const (
	queryResources queryKind = iota + 1
	queryCommits
)

type queryShape [sha256.Size]byte

type queryCursorLease struct {
	kind      queryKind
	shape     queryShape
	offset    uint64
	expiresAt time.Time
}

type queryScope struct {
	workspace *workspaceState
}

func (scope queryScope) WorkspaceID() artifact.UUID    { return scope.workspace.workspaceID }
func (scope queryScope) Root() string                  { return scope.workspace.root }
func (scope queryScope) ConfigRevision() digest.Digest { return scope.workspace.configRevision }

func (workspace *Workspace) Snapshot(ctx context.Context) (WorkspaceSnapshot, error) {
	state, queryContext, done, err := workspace.beginQuery(ctx)
	if err != nil {
		return WorkspaceSnapshot{}, err
	}
	defer done()

	data, err := callQuery(func() (SnapshotData, error) {
		return workspace.host.queries.Snapshot(queryContext, queryScope{workspace: state})
	})
	if err != nil {
		return WorkspaceSnapshot{}, err
	}
	if err := queryContext.Err(); err != nil {
		return WorkspaceSnapshot{}, err
	}
	frontier, err := validateAndCloneFrontier(data.Frontier, true)
	if err != nil || (len(frontier) == 0 && (data.ResourceCount != 0 || data.CommitCount != 0)) {
		return WorkspaceSnapshot{}, ErrInvalidQueryResult
	}
	return WorkspaceSnapshot{
		Frontier: frontier, ConfigRevision: state.configRevision,
		ResourceCount: data.ResourceCount, CommitCount: data.CommitCount,
	}, nil
}

func (workspace *Workspace) ListResources(ctx context.Context, request ListResourcesRequest) (ResourcePage, error) {
	if err := validateSHA256(request.AtCommit); err != nil {
		return ResourcePage{}, ErrInvalidQuery
	}
	pageSize, err := normalizePageSize(request.PageSize)
	if err != nil {
		return ResourcePage{}, err
	}
	shape := makeQueryShape(queryResources, pageSize, []digest.Digest{request.AtCommit})
	state, queryContext, done, err := workspace.beginQuery(ctx)
	if err != nil {
		return ResourcePage{}, err
	}
	defer done()
	offset, err := state.consumeQueryCursor(request.Cursor, queryResources, shape, workspace.host.now())
	if err != nil {
		return ResourcePage{}, err
	}

	data, err := callQuery(func() (ResourcePageData, error) {
		return workspace.host.queries.ListResources(queryContext, queryScope{workspace: state}, ResourcePageQuery{
			AtCommit: request.AtCommit, Offset: offset, Limit: pageSize,
		})
	})
	if err != nil {
		return ResourcePage{}, err
	}
	if err := queryContext.Err(); err != nil {
		return ResourcePage{}, err
	}
	resources, err := validateAndCloneResources(data.Resources, pageSize)
	if err != nil || !validContinuation(len(resources), data.More, offset, data.NextOffset) {
		return ResourcePage{}, ErrInvalidQueryResult
	}
	page := ResourcePage{Resources: resources}
	if data.More {
		page.Next, err = workspace.issueQueryCursor(state, queryResources, shape, data.NextOffset)
		if err != nil {
			return ResourcePage{}, err
		}
	}
	return page, nil
}

func (workspace *Workspace) ListCommits(ctx context.Context, request ListCommitsRequest) (CommitPage, error) {
	frontier, err := validateAndCloneFrontier(request.Frontier, false)
	if err != nil {
		return CommitPage{}, ErrInvalidQuery
	}
	pageSize, err := normalizePageSize(request.PageSize)
	if err != nil {
		return CommitPage{}, err
	}
	shape := makeQueryShape(queryCommits, pageSize, frontier)
	state, queryContext, done, err := workspace.beginQuery(ctx)
	if err != nil {
		return CommitPage{}, err
	}
	defer done()
	offset, err := state.consumeQueryCursor(request.Cursor, queryCommits, shape, workspace.host.now())
	if err != nil {
		return CommitPage{}, err
	}

	data, err := callQuery(func() (CommitPageData, error) {
		return workspace.host.queries.ListCommits(queryContext, queryScope{workspace: state}, CommitPageQuery{
			Frontier: append([]digest.Digest(nil), frontier...), Offset: offset, Limit: pageSize,
		})
	})
	if err != nil {
		return CommitPage{}, err
	}
	if err := queryContext.Err(); err != nil {
		return CommitPage{}, err
	}
	commits, err := validateAndCloneCommits(data.Commits, pageSize)
	if err != nil || !validContinuation(len(commits), data.More, offset, data.NextOffset) {
		return CommitPage{}, ErrInvalidQueryResult
	}
	page := CommitPage{Commits: commits}
	if data.More {
		page.Next, err = workspace.issueQueryCursor(state, queryCommits, shape, data.NextOffset)
		if err != nil {
			return CommitPage{}, err
		}
	}
	return page, nil
}

func (workspace *Workspace) GetResource(ctx context.Context, request GetResourceRequest) (ResourceMetadata, error) {
	if err := validateSHA256(request.AtCommit); err != nil {
		return ResourceMetadata{}, ErrInvalidQuery
	}
	if err := request.UID.Validate(); err != nil {
		return ResourceMetadata{}, ErrInvalidQuery
	}
	state, queryContext, done, err := workspace.beginQuery(ctx)
	if err != nil {
		return ResourceMetadata{}, err
	}
	defer done()

	resource, err := callQuery(func() (ResourceMetadata, error) {
		return workspace.host.queries.GetResource(queryContext, queryScope{workspace: state}, ResourceQuery(request))
	})
	if err != nil {
		return ResourceMetadata{}, err
	}
	if err := queryContext.Err(); err != nil {
		return ResourceMetadata{}, err
	}
	if err := validateResourceMetadata(resource); err != nil || resource.UID != request.UID {
		return ResourceMetadata{}, ErrInvalidQueryResult
	}
	return cloneResourceMetadata(resource), nil
}

func (workspace *Workspace) beginQuery(ctx context.Context) (*workspaceState, context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, nil, fmt.Errorf("%w: nil context", ErrInvalidQuery)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	state, err := workspace.validState()
	if err != nil {
		return nil, nil, nil, err
	}
	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		return nil, nil, nil, ErrWorkspaceClosed
	}
	hostContext := state.hostContext
	state.mu.Unlock()
	queryContext, cancel := context.WithCancel(hostContext)
	stopCaller := context.AfterFunc(ctx, cancel)
	done := func() {
		stopCaller()
		cancel()
	}
	return state, queryContext, done, nil
}

func normalizePageSize(value uint32) (uint32, error) {
	if value == 0 {
		return DefaultQueryPageSize, nil
	}
	if value > MaxQueryPageSize {
		return 0, ErrInvalidQuery
	}
	return value, nil
}

func (state *workspaceState) consumeQueryCursor(cursor QueryCursor, kind queryKind, shape queryShape, now time.Time) (uint64, error) {
	if cursor == "" {
		return 0, nil
	}
	if err := cursor.validate(); err != nil {
		return 0, ErrInvalidQueryCursor
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return 0, ErrWorkspaceClosed
	}
	lease, exists := state.queryCursors[cursor]
	if !exists {
		return 0, ErrInvalidQueryCursor
	}
	delete(state.queryCursors, cursor)
	if !now.Before(lease.expiresAt) {
		return 0, ErrQueryCursorExpired
	}
	if lease.kind != kind || lease.shape != shape {
		return 0, ErrInvalidQueryCursor
	}
	return lease.offset, nil
}

func (workspace *Workspace) issueQueryCursor(state *workspaceState, kind queryKind, shape queryShape, offset uint64) (QueryCursor, error) {
	for range 16 {
		value, err := newUUID()
		if err != nil {
			return "", err
		}
		cursor := QueryCursor(value)
		now := workspace.host.now()
		state.mu.Lock()
		if state.closed {
			state.mu.Unlock()
			return "", ErrWorkspaceClosed
		}
		state.purgeExpiredQueryCursors(now)
		if len(state.queryCursors) >= MaxQueryCursorsPerWorkspace {
			state.mu.Unlock()
			return "", ErrQueryCursorLimit
		}
		if _, exists := state.queryCursors[cursor]; exists {
			state.mu.Unlock()
			continue
		}
		state.queryCursors[cursor] = queryCursorLease{
			kind: kind, shape: shape, offset: offset, expiresAt: now.Add(workspace.host.queryCursorTTL),
		}
		state.mu.Unlock()
		return cursor, nil
	}
	return "", errors.New("host: generate unique query cursor")
}

func (state *workspaceState) purgeExpiredQueryCursors(now time.Time) {
	for cursor, lease := range state.queryCursors {
		if !now.Before(lease.expiresAt) {
			delete(state.queryCursors, cursor)
		}
	}
}

func makeQueryShape(kind queryKind, pageSize uint32, pins []digest.Digest) queryShape {
	hash := sha256.New()
	_, _ = hash.Write([]byte{byte(kind)})
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], pageSize)
	_, _ = hash.Write(size[:])
	for _, pin := range pins {
		_, _ = hash.Write([]byte(pin))
		_, _ = hash.Write([]byte{0})
	}
	var shape queryShape
	copy(shape[:], hash.Sum(nil))
	return shape
}

func validateAndCloneFrontier(frontier []digest.Digest, allowEmpty bool) ([]digest.Digest, error) {
	if (!allowEmpty && len(frontier) == 0) || len(frontier) > MaxQueryFrontier {
		return nil, ErrInvalidQuery
	}
	cloned := append([]digest.Digest(nil), frontier...)
	for _, value := range cloned {
		if err := validateSHA256(value); err != nil {
			return nil, err
		}
	}
	sort.Slice(cloned, func(left, right int) bool { return cloned[left] < cloned[right] })
	for index := 1; index < len(cloned); index++ {
		if cloned[index] == cloned[index-1] {
			return nil, ErrInvalidQuery
		}
	}
	return cloned, nil
}

func validateAndCloneResources(resources []ResourceMetadata, limit uint32) ([]ResourceMetadata, error) {
	if len(resources) > int(limit) {
		return nil, ErrInvalidQueryResult
	}
	cloned := make([]ResourceMetadata, len(resources))
	seen := make(map[artifact.UUID]struct{}, len(resources))
	for index, resource := range resources {
		if err := validateResourceMetadata(resource); err != nil {
			return nil, err
		}
		if _, exists := seen[resource.UID]; exists {
			return nil, ErrInvalidQueryResult
		}
		seen[resource.UID] = struct{}{}
		cloned[index] = cloneResourceMetadata(resource)
	}
	return cloned, nil
}

func validateResourceMetadata(resource ResourceMetadata) error {
	if resource.Kind != artifact.KindResource && resource.Kind != artifact.KindCollection {
		return ErrInvalidQueryResult
	}
	if err := resource.UID.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	if err := resource.Schema.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	if err := resource.Metadata.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	if err := resource.Sealed.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	return nil
}

func cloneResourceMetadata(resource ResourceMetadata) ResourceMetadata {
	resource.Metadata.Labels = cloneStringMap(resource.Metadata.Labels)
	resource.Metadata.Annotations = cloneStringMap(resource.Metadata.Annotations)
	return resource
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func validateAndCloneCommits(commits []CommitMetadata, limit uint32) ([]CommitMetadata, error) {
	if len(commits) > int(limit) {
		return nil, ErrInvalidQueryResult
	}
	cloned := make([]CommitMetadata, len(commits))
	seen := make(map[digest.Digest]struct{}, len(commits))
	for index, commit := range commits {
		if err := validateCommitMetadata(commit); err != nil {
			return nil, err
		}
		if _, exists := seen[commit.ID]; exists {
			return nil, ErrInvalidQueryResult
		}
		seen[commit.ID] = struct{}{}
		commit.Parents = append([]digest.Digest(nil), commit.Parents...)
		cloned[index] = commit
	}
	return cloned, nil
}

func validateCommitMetadata(value CommitMetadata) error {
	if err := validateSHA256(value.ID); err != nil {
		return ErrInvalidQueryResult
	}
	if err := value.Root.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	if err := value.Policy.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	if len(value.Parents) > commitmodel.MaxParents {
		return ErrInvalidQueryResult
	}
	seenParents := make(map[digest.Digest]struct{}, len(value.Parents))
	for _, parent := range value.Parents {
		if err := validateSHA256(parent); err != nil {
			return ErrInvalidQueryResult
		}
		if _, exists := seenParents[parent]; exists {
			return ErrInvalidQueryResult
		}
		seenParents[parent] = struct{}{}
	}
	if value.Actor == "" || len(value.Actor) > commitmodel.MaxActorBytes || !utf8.ValidString(value.Actor) || !norm.NFC.IsNormalString(value.Actor) ||
		strings.IndexFunc(value.Actor, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return ErrInvalidQueryResult
	}
	if err := value.DeviceID.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	if err := value.OperationID.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	if err := value.Timestamp.Validate(); err != nil {
		return ErrInvalidQueryResult
	}
	return nil
}

func validContinuation(itemCount int, more bool, offset, next uint64) bool {
	if !more {
		return next == 0
	}
	return itemCount > 0 && next > offset
}

func callQuery[Result any](query func() (Result, error)) (result Result, returnedErr error) {
	defer func() {
		if recover() != nil {
			var zero Result
			result = zero
			returnedErr = errors.New("host: query executor panic")
		}
	}()
	return query()
}

var _ QueryExecution = queryScope{}

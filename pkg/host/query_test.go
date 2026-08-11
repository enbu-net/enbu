package host

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/opencontainers/go-digest"
)

const (
	testSecondResourceID = artifact.UUID("55555555-5555-4555-8555-555555555555")
	testDeviceID         = artifact.UUID("66666666-6666-4666-8666-666666666666")
	testOperationUUID    = artifact.UUID("77777777-7777-4777-8777-777777777777")
)

type queryExecutorFuncs struct {
	snapshot      func(context.Context, QueryExecution) (SnapshotData, error)
	listResources func(context.Context, QueryExecution, ResourcePageQuery) (ResourcePageData, error)
	listCommits   func(context.Context, QueryExecution, CommitPageQuery) (CommitPageData, error)
	getResource   func(context.Context, QueryExecution, ResourceQuery) (ResourceMetadata, error)
}

func (executor queryExecutorFuncs) Snapshot(ctx context.Context, execution QueryExecution) (SnapshotData, error) {
	if executor.snapshot == nil {
		return SnapshotData{}, nil
	}
	return executor.snapshot(ctx, execution)
}

func (executor queryExecutorFuncs) ListResources(ctx context.Context, execution QueryExecution, query ResourcePageQuery) (ResourcePageData, error) {
	if executor.listResources == nil {
		return ResourcePageData{}, nil
	}
	return executor.listResources(ctx, execution, query)
}

func (executor queryExecutorFuncs) ListCommits(ctx context.Context, execution QueryExecution, query CommitPageQuery) (CommitPageData, error) {
	if executor.listCommits == nil {
		return CommitPageData{}, nil
	}
	return executor.listCommits(ctx, execution, query)
}

func (executor queryExecutorFuncs) GetResource(ctx context.Context, execution QueryExecution, query ResourceQuery) (ResourceMetadata, error) {
	if executor.getResource == nil {
		return ResourceMetadata{}, ErrResourceNotFound
	}
	return executor.getResource(ctx, execution, query)
}

func newQueryTestHost(t *testing.T, queries QueryExecutor) *Host {
	t.Helper()
	host, err := New(executorFunc(func(context.Context, Execution, Action) (Outcome, error) {
		return successfulCommitOutcome(), nil
	}), queries)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func queryResource(uid artifact.UUID, name string) ResourceMetadata {
	return ResourceMetadata{
		Kind: artifact.KindResource, UID: uid, Schema: testType("Opaque"),
		Metadata: artifact.Metadata{Name: name, Labels: map[string]string{"tier": "private"}, Annotations: map[string]string{"note": "metadata"}},
		Sealed:   testSealed(name),
	}
}

func queryCommit(name string, parents ...digest.Digest) CommitMetadata {
	return CommitMetadata{
		ID: digest.FromString(name), Root: testSealed(name + "-root"), Policy: testSealed(name + "-policy"),
		Parents: append([]digest.Digest(nil), parents...), Actor: "alice@example.com", DeviceID: testDeviceID,
		OperationID: testOperationUUID, Timestamp: commitmodel.NewTimestamp(time.Unix(1_000, 0)),
	}
}

func TestSnapshotReturnsOnlyCanonicalDeepCopiedMetadata(t *testing.T) {
	first := digest.FromString("first")
	second := digest.FromString("second")
	backendFrontier := []digest.Digest{second, first}
	host := newQueryTestHost(t, queryExecutorFuncs{
		snapshot: func(_ context.Context, execution QueryExecution) (SnapshotData, error) {
			if execution.WorkspaceID() != testWorkspaceID || execution.ConfigRevision() != digest.FromString("config") {
				t.Fatalf("query execution identity = %q/%q", execution.WorkspaceID(), execution.ConfigRevision())
			}
			return SnapshotData{Frontier: backendFrontier, ResourceCount: 3, CommitCount: 2}, nil
		},
	})
	workspace := openWorkspace(t, host)
	snapshot, err := workspace.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	backendFrontier[0] = digest.FromString("mutated")
	wantFrontier := []digest.Digest{first, second}
	sort.Slice(wantFrontier, func(left, right int) bool { return wantFrontier[left] < wantFrontier[right] })
	if len(snapshot.Frontier) != 2 || snapshot.Frontier[0] != wantFrontier[0] || snapshot.Frontier[1] != wantFrontier[1] {
		t.Fatalf("frontier = %v", snapshot.Frontier)
	}
	if snapshot.ConfigRevision != digest.FromString("config") || snapshot.ResourceCount != 3 || snapshot.CommitCount != 2 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestResourceCursorIsSessionBoundSingleUseAndDeepCopiesMetadata(t *testing.T) {
	commit := digest.FromString("commit")
	firstResource := queryResource(testResourceID, "first")
	secondResource := queryResource(testSecondResourceID, "second")
	var calls atomic.Int32
	host := newQueryTestHost(t, queryExecutorFuncs{
		listResources: func(_ context.Context, _ QueryExecution, query ResourcePageQuery) (ResourcePageData, error) {
			switch call := calls.Add(1); call {
			case 1:
				if query.Offset != 0 || query.Limit != 2 || query.AtCommit != commit {
					t.Fatalf("first query = %#v", query)
				}
				return ResourcePageData{Resources: []ResourceMetadata{firstResource}, More: true, NextOffset: 7}, nil
			case 2:
				if query.Offset != 7 || query.Limit != 2 || query.AtCommit != commit {
					t.Fatalf("second query = %#v", query)
				}
				return ResourcePageData{Resources: []ResourceMetadata{secondResource}}, nil
			default:
				t.Fatalf("unexpected query call %d", call)
				return ResourcePageData{}, nil
			}
		},
	})
	firstWorkspace := openWorkspace(t, host)
	secondWorkspace := openWorkspace(t, host)
	request := ListResourcesRequest{AtCommit: commit, PageSize: 2}
	page, err := firstWorkspace.ListResources(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if page.Next == "" || len(page.Resources) != 1 {
		t.Fatalf("first page = %#v", page)
	}
	firstResource.Metadata.Labels["tier"] = "mutated"
	if page.Resources[0].Metadata.Labels["tier"] != "private" {
		t.Fatal("backend metadata mutation changed returned page")
	}
	if _, err := secondWorkspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 2, Cursor: page.Next}); !errors.Is(err, ErrInvalidQueryCursor) {
		t.Fatalf("cross-session cursor error = %v", err)
	}
	secondPage, err := firstWorkspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 2, Cursor: page.Next})
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage.Resources) != 1 || secondPage.Resources[0].UID != testSecondResourceID || secondPage.Next != "" {
		t.Fatalf("second page = %#v", secondPage)
	}
	if _, err := firstWorkspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 2, Cursor: page.Next}); !errors.Is(err, ErrInvalidQueryCursor) {
		t.Fatalf("reused cursor error = %v", err)
	}
}

func TestQueryCursorBindsShapeAndIsConsumedOnMismatch(t *testing.T) {
	commit := digest.FromString("commit")
	var calls atomic.Int32
	host := newQueryTestHost(t, queryExecutorFuncs{
		listResources: func(context.Context, QueryExecution, ResourcePageQuery) (ResourcePageData, error) {
			calls.Add(1)
			return ResourcePageData{Resources: []ResourceMetadata{queryResource(testResourceID, "first")}, More: true, NextOffset: 1}, nil
		},
	})
	workspace := openWorkspace(t, host)
	page, err := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 3, Cursor: page.Next}); !errors.Is(err, ErrInvalidQueryCursor) {
		t.Fatalf("shape mismatch error = %v", err)
	}
	if _, err := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 2, Cursor: page.Next}); !errors.Is(err, ErrInvalidQueryCursor) {
		t.Fatalf("mismatched cursor was not consumed: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("backend calls = %d", calls.Load())
	}
}

func TestQueryCursorExpiresAndCloseInvalidatesState(t *testing.T) {
	now := time.Unix(1_000, 0)
	queries := queryExecutorFuncs{
		listResources: func(context.Context, QueryExecution, ResourcePageQuery) (ResourcePageData, error) {
			return ResourcePageData{Resources: []ResourceMetadata{queryResource(testResourceID, "first")}, More: true, NextOffset: 1}, nil
		},
	}
	host, err := newHost(
		executorFunc(func(context.Context, Execution, Action) (Outcome, error) { return successfulCommitOutcome(), nil }),
		queries, func() time.Time { return now }, time.Minute, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	workspace := openWorkspace(t, host)
	request := ListResourcesRequest{AtCommit: digest.FromString("commit"), PageSize: 1}
	page, err := workspace.ListResources(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: request.AtCommit, PageSize: 1, Cursor: page.Next}); !errors.Is(err, ErrQueryCursorExpired) {
		t.Fatalf("expired cursor error = %v", err)
	}

	now = now.Add(time.Second)
	page, err = workspace.ListResources(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := workspace.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	workspace.state.mu.Lock()
	cursorCount := len(workspace.state.queryCursors)
	workspace.state.mu.Unlock()
	if cursorCount != 0 {
		t.Fatalf("Close retained %d query cursors", cursorCount)
	}
	if _, err := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: request.AtCommit, PageSize: 1, Cursor: page.Next}); !errors.Is(err, ErrWorkspaceClosed) {
		t.Fatalf("query after Close error = %v", err)
	}
}

func TestQueryCursorCanBeClaimedByOnlyOneConcurrentCaller(t *testing.T) {
	commit := digest.FromString("commit")
	var calls atomic.Int32
	host := newQueryTestHost(t, queryExecutorFuncs{
		listResources: func(context.Context, QueryExecution, ResourcePageQuery) (ResourcePageData, error) {
			call := calls.Add(1)
			if call == 1 {
				return ResourcePageData{Resources: []ResourceMetadata{queryResource(testResourceID, "first")}, More: true, NextOffset: 1}, nil
			}
			return ResourcePageData{Resources: []ResourceMetadata{queryResource(testSecondResourceID, "second")}}, nil
		},
	})
	workspace := openWorkspace(t, host)
	page, err := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	var successes atomic.Int32
	var invalid atomic.Int32
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, queryErr := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 1, Cursor: page.Next})
			switch {
			case queryErr == nil:
				successes.Add(1)
			case errors.Is(queryErr, ErrInvalidQueryCursor):
				invalid.Add(1)
			default:
				t.Errorf("query error = %v", queryErr)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || invalid.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("successes=%d invalid=%d backend calls=%d", successes.Load(), invalid.Load(), calls.Load())
	}
}

func TestQueryCursorStateIsBounded(t *testing.T) {
	host := newQueryTestHost(t, queryExecutorFuncs{})
	workspace := openWorkspace(t, host)
	workspace.state.mu.Lock()
	for range MaxQueryCursorsPerWorkspace {
		value, err := newUUID()
		if err != nil {
			workspace.state.mu.Unlock()
			t.Fatal(err)
		}
		workspace.state.queryCursors[QueryCursor(value)] = queryCursorLease{
			kind: queryResources, expiresAt: time.Now().Add(time.Hour),
		}
	}
	workspace.state.mu.Unlock()
	if _, err := workspace.issueQueryCursor(workspace.state, queryResources, queryShape{}, 1); !errors.Is(err, ErrQueryCursorLimit) {
		t.Fatalf("cursor limit error = %v", err)
	}
}

func TestListCommitsCanonicalizesFrontierAndDeepCopiesParents(t *testing.T) {
	first := digest.FromString("frontier-first")
	second := digest.FromString("frontier-second")
	parent := digest.FromString("parent")
	backendCommit := queryCommit("commit", parent)
	wantFrontier := []digest.Digest{first, second}
	sort.Slice(wantFrontier, func(left, right int) bool { return wantFrontier[left] < wantFrontier[right] })
	host := newQueryTestHost(t, queryExecutorFuncs{
		listCommits: func(_ context.Context, _ QueryExecution, query CommitPageQuery) (CommitPageData, error) {
			if len(query.Frontier) != 2 || query.Frontier[0] != wantFrontier[0] || query.Frontier[1] != wantFrontier[1] {
				t.Fatalf("frontier = %v", query.Frontier)
			}
			query.Frontier[0] = digest.FromString("executor-mutation")
			return CommitPageData{Commits: []CommitMetadata{backendCommit}}, nil
		},
	})
	workspace := openWorkspace(t, host)
	requestFrontier := []digest.Digest{second, first}
	page, err := workspace.ListCommits(context.Background(), ListCommitsRequest{Frontier: requestFrontier, PageSize: 5})
	if err != nil {
		t.Fatal(err)
	}
	backendCommit.Parents[0] = digest.FromString("mutated")
	if len(page.Commits) != 1 || page.Commits[0].Parents[0] != parent {
		t.Fatalf("commit page = %#v", page)
	}
	if requestFrontier[0] != second || requestFrontier[1] != first {
		t.Fatalf("caller frontier mutated: %v", requestFrontier)
	}
}

func TestGetResourceValidatesIdentityAndDeepCopiesMetadata(t *testing.T) {
	backend := queryResource(testResourceID, "resource")
	host := newQueryTestHost(t, queryExecutorFuncs{
		getResource: func(_ context.Context, _ QueryExecution, query ResourceQuery) (ResourceMetadata, error) {
			if query.AtCommit != digest.FromString("commit") || query.UID != testResourceID {
				t.Fatalf("resource query = %#v", query)
			}
			return backend, nil
		},
	})
	workspace := openWorkspace(t, host)
	resource, err := workspace.GetResource(context.Background(), GetResourceRequest{AtCommit: digest.FromString("commit"), UID: testResourceID})
	if err != nil {
		t.Fatal(err)
	}
	backend.Metadata.Annotations["note"] = "mutated"
	if resource.Metadata.Annotations["note"] != "metadata" {
		t.Fatal("backend metadata mutation changed GetResource result")
	}

	host = newQueryTestHost(t, queryExecutorFuncs{
		getResource: func(context.Context, QueryExecution, ResourceQuery) (ResourceMetadata, error) {
			return queryResource(testSecondResourceID, "wrong"), nil
		},
	})
	workspace = openWorkspace(t, host)
	if _, err := workspace.GetResource(context.Background(), GetResourceRequest{AtCommit: digest.FromString("commit"), UID: testResourceID}); !errors.Is(err, ErrInvalidQueryResult) {
		t.Fatalf("mismatched UID error = %v", err)
	}
}

func TestQueryBoundsAndMalformedContinuationFailClosed(t *testing.T) {
	var calls atomic.Int32
	host := newQueryTestHost(t, queryExecutorFuncs{
		listResources: func(context.Context, QueryExecution, ResourcePageQuery) (ResourcePageData, error) {
			calls.Add(1)
			return ResourcePageData{Resources: []ResourceMetadata{queryResource(testResourceID, "first")}, More: true}, nil
		},
	})
	workspace := openWorkspace(t, host)
	commit := digest.FromString("commit")
	if _, err := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: MaxQueryPageSize + 1}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("oversized page error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("oversized query reached backend")
	}
	if _, err := workspace.ListResources(context.Background(), ListResourcesRequest{AtCommit: commit, PageSize: 1}); !errors.Is(err, ErrInvalidQueryResult) {
		t.Fatalf("malformed continuation error = %v", err)
	}
}

func TestCloseCancelsInFlightQuery(t *testing.T) {
	started := make(chan struct{})
	host := newQueryTestHost(t, queryExecutorFuncs{
		snapshot: func(ctx context.Context, _ QueryExecution) (SnapshotData, error) {
			close(started)
			<-ctx.Done()
			return SnapshotData{}, ctx.Err()
		},
	})
	workspace := openWorkspace(t, host)
	result := make(chan error, 1)
	go func() {
		_, err := workspace.Snapshot(context.Background())
		result <- err
	}()
	<-started
	if err := workspace.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("query error after Close = %v", err)
	}
}

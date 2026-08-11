package host

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	testWorkspaceID  = artifact.UUID("11111111-1111-4111-8111-111111111111")
	testResourceID   = artifact.UUID("22222222-2222-4222-8222-222222222222")
	testPolicyID     = artifact.UUID("33333333-3333-4333-8333-333333333333")
	testConflictID   = artifact.UUID("44444444-4444-4444-8444-444444444444")
	testInputHandle  = InputHandle("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	testOutputHandle = OutputHandle("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
)

type executorFunc func(context.Context, Execution, Action) (Outcome, error)

func (function executorFunc) Execute(ctx context.Context, execution Execution, action Action) (Outcome, error) {
	return function(ctx, execution, action)
}

func (executorFunc) Finalize(context.Context, Execution, Action, Outcome, error) error { return nil }

type lifecycleExecutor struct {
	execute  func(context.Context, Execution, Action) (Outcome, error)
	finalize func(context.Context, Execution, Action, Outcome, error) error
}

func (executor lifecycleExecutor) Execute(ctx context.Context, execution Execution, action Action) (Outcome, error) {
	return executor.execute(ctx, execution, action)
}

func (executor lifecycleExecutor) Finalize(ctx context.Context, execution Execution, action Action, outcome Outcome, executeErr error) error {
	return executor.finalize(ctx, execution, action, outcome, executeErr)
}

type queryExecutorStub struct{}

func (queryExecutorStub) Snapshot(context.Context, QueryExecution) (SnapshotData, error) {
	return SnapshotData{}, nil
}

func (queryExecutorStub) ListResources(context.Context, QueryExecution, ResourcePageQuery) (ResourcePageData, error) {
	return ResourcePageData{}, nil
}

func (queryExecutorStub) ListCommits(context.Context, QueryExecution, CommitPageQuery) (CommitPageData, error) {
	return CommitPageData{}, nil
}

func (queryExecutorStub) GetResource(context.Context, QueryExecution, ResourceQuery) (ResourceMetadata, error) {
	return ResourceMetadata{}, ErrResourceNotFound
}

type byteSource struct {
	data  []byte
	opens atomic.Int32
}

func (source *byteSource) Open(context.Context) (io.ReadCloser, error) {
	source.opens.Add(1)
	return io.NopCloser(bytes.NewReader(append([]byte(nil), source.data...))), nil
}

type memoryOutput struct {
	bytes.Buffer
	commits atomic.Int32
	aborts  atomic.Int32
}

func (output *memoryOutput) Commit() error { output.commits.Add(1); return nil }
func (output *memoryOutput) Abort() error  { output.aborts.Add(1); return nil }

type memoryTarget struct{ output *memoryOutput }

func (target memoryTarget) Open(context.Context) (Output, error) { return target.output, nil }

func testType(kind string) artifact.TypeRef {
	return artifact.TypeRef{Group: "schemas.enbu.net", Version: "v1alpha1", Kind: kind}
}

func testRole() artifact.TypeRef {
	return artifact.TypeRef{Group: "operations.enbu.net", Version: "v1alpha1", Kind: "Input"}
}

func testSealed(label string) artifact.SealedRef {
	return artifact.SealedRef{
		Revision: digest.FromString(label + "-revision"),
		Material: digest.FromString(label + "-material"),
		Grant:    digest.FromString(label + "-grant"),
	}
}

func testDraft(kind artifact.Kind, uid artifact.UUID, schema artifact.TypeRef) DraftResource {
	return DraftResource{Kind: kind, UID: uid, Schema: schema, Metadata: artifact.Metadata{Name: "test"}}
}

func testTransformOutput() TransformOutput {
	return TransformOutput{
		Slot: "result", UID: testConflictID, Metadata: artifact.Metadata{Name: "result"},
		Parent: testWorkspaceID, ExpectedParent: testSealed("parent"),
		EdgeID: testPolicyID, EdgeName: "result", Relation: artifact.MemberRelation(),
		Payloads: []TransformPayload{{Name: "content", MediaType: "application/octet-stream"}},
	}
}

func successfulCommitOutcome() Outcome {
	return Outcome{Commit: &CommitResult{Commit: digest.FromString("commit-result"), Root: testSealed("root")}}
}

func openWorkspace(t *testing.T, host *Host) *Workspace {
	t.Helper()
	root := t.TempDir()
	workspace, err := host.OpenWorkspace(context.Background(), OpenWorkspaceRequest{
		WorkspaceID: testWorkspaceID, Root: root, ConfigRevision: digest.FromString("config"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return workspace
}

func newTestHost(t *testing.T, executor Executor) *Host {
	t.Helper()
	host, err := New(executor, queryExecutorStub{})
	if err != nil {
		t.Fatal(err)
	}
	return host
}

func validRestoreAction() RestoreAction {
	return RestoreAction{BaseCommit: digest.FromString("base"), SourceCommit: digest.FromString("source")}
}

func TestActionUnionValidatesAllVariants(t *testing.T) {
	root := testDraft(artifact.KindCollection, testResourceID, testType("Workspace"))
	policy := testDraft(artifact.KindResource, testPolicyID, testType("RegoPolicy"))
	actions := []Action{
		InitializeAction{OwnerEnrollment: digest.FromString("owner"), Root: root, Policy: policy},
		ApplyAction{BaseCommit: digest.FromString("base"), Changes: []GraphChange{{Create: &CreateResource{Draft: testDraft(artifact.KindResource, testResourceID, testType("Opaque"))}}}},
		TransformAction{BaseCommit: digest.FromString("base"), Transform: TransformRef{Builtin: testType("Normalize")}, Inputs: []PinnedInput{{Role: testRole(), UID: testResourceID, Sealed: testSealed("input"), Payload: "content"}}, Outputs: []TransformOutput{testTransformOutput()}},
		MaterializeAction{AtCommit: digest.FromString("commit"), Target: testResourceID, Format: testType("DotEnv"), Destination: testOutputHandle},
		ChangeAccessAction{BaseCommit: digest.FromString("base"), Targets: []artifact.UUID{testResourceID}, Mode: AccessGrant, Candidates: []EnrollmentRef{{Digest: digest.FromString("candidate")}}},
		MergeAction{Heads: []digest.Digest{digest.FromString("left"), digest.FromString("right")}, Resolutions: []ConflictResolution{{ConflictID: testConflictID, SelectCommit: digest.FromString("left")}}},
		validRestoreAction(),
	}
	for _, action := range actions {
		cloned, err := cloneAction(action)
		if err != nil {
			t.Fatalf("clone %s: %v", action.Kind(), err)
		}
		if err := cloned.validate(); err != nil {
			t.Fatalf("validate %s: %v", action.Kind(), err)
		}
	}
}

func TestTransformRejectsSameRoleAndUIDAtDifferentRevisions(t *testing.T) {
	action := TransformAction{
		BaseCommit: digest.FromString("base"),
		Transform:  TransformRef{Builtin: testType("Normalize")},
		Inputs: []PinnedInput{
			{Role: testRole(), UID: testResourceID, Sealed: testSealed("first"), Payload: "content"},
			{Role: testRole(), UID: testResourceID, Sealed: testSealed("second"), Payload: "content"},
		},
		Outputs: []TransformOutput{testTransformOutput()},
	}
	if err := action.validate(); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("duplicate role and UID error = %v", err)
	}
}

func TestActionsRequirePinnedBaseOrCommit(t *testing.T) {
	tests := []Action{
		ApplyAction{Changes: []GraphChange{{Create: &CreateResource{Draft: testDraft(artifact.KindResource, testResourceID, testType("Opaque"))}}}},
		TransformAction{Transform: TransformRef{Builtin: testType("Normalize")}, Inputs: []PinnedInput{{Role: testRole(), UID: testResourceID, Sealed: testSealed("input"), Payload: "content"}}, Outputs: []TransformOutput{testTransformOutput()}},
		MaterializeAction{Target: testResourceID, Format: testType("DotEnv"), Destination: testOutputHandle},
		ChangeAccessAction{Targets: []artifact.UUID{testResourceID}, Mode: AccessGrant, Candidates: []EnrollmentRef{{Digest: digest.FromString("candidate")}}},
		RestoreAction{SourceCommit: digest.FromString("source")},
	}
	for _, action := range tests {
		if err := action.validate(); !errors.Is(err, ErrInvalidAction) {
			t.Fatalf("%s missing commit error = %v", action.Kind(), err)
		}
	}
}

func TestApplyBoundsAreEnforcedBeforeExecution(t *testing.T) {
	executed := atomic.Bool{}
	host := newTestHost(t, executorFunc(func(context.Context, Execution, Action) (Outcome, error) {
		executed.Store(true)
		return successfulCommitOutcome(), nil
	}))
	workspace := openWorkspace(t, host)
	changes := make([]GraphChange, MaxActionChanges+1)
	for index := range changes {
		changes[index] = GraphChange{Delete: &DeleteResource{UID: testResourceID, Expected: testSealed("delete")}}
	}
	_, err := workspace.Start(context.Background(), ApplyAction{BaseCommit: digest.FromString("base"), Changes: changes})
	if !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("oversized action error = %v", err)
	}
	if executed.Load() {
		t.Fatal("executor received oversized action")
	}
}

func TestStartDeepCopiesMutableActionData(t *testing.T) {
	allowInspect := make(chan struct{})
	received := make(chan string, 1)
	host := newTestHost(t, executorFunc(func(_ context.Context, _ Execution, action Action) (Outcome, error) {
		<-allowInspect
		apply := action.(ApplyAction)
		received <- apply.Changes[0].Create.Draft.Metadata.Labels["tier"]
		return successfulCommitOutcome(), nil
	}))
	workspace := openWorkspace(t, host)
	draft := testDraft(artifact.KindResource, testResourceID, testType("Opaque"))
	draft.Metadata.Labels = map[string]string{"tier": "original"}
	action := ApplyAction{BaseCommit: digest.FromString("base"), Changes: []GraphChange{{Create: &CreateResource{Draft: draft}}}}
	id, err := workspace.Start(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	action.Changes[0].Create.Draft.Metadata.Labels["tier"] = "mutated"
	close(allowInspect)
	if _, err := workspace.Wait(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if value := <-received; value != "original" {
		t.Fatalf("executor observed caller mutation %q", value)
	}
}

func TestExecutionCarriesHostGeneratedOperationID(t *testing.T) {
	received := make(chan artifact.UUID, 1)
	host := newTestHost(t, executorFunc(func(_ context.Context, execution Execution, _ Action) (Outcome, error) {
		received <- execution.OperationID()
		return successfulCommitOutcome(), nil
	}))
	workspace := openWorkspace(t, host)
	id, err := workspace.Start(context.Background(), validRestoreAction())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	operationID := <-received
	if err := operationID.Validate(); err != nil {
		t.Fatalf("executor operation ID is invalid: %v", err)
	}
	if operationID != artifact.UUID(id) {
		t.Fatalf("executor operation ID = %q, Start returned %q", operationID, id)
	}
}

func TestInputHandlesAreSessionScopedAndSingleUse(t *testing.T) {
	host := newTestHost(t, executorFunc(func(_ context.Context, execution Execution, action Action) (Outcome, error) {
		transform := action.(TransformAction)
		reader, err := execution.OpenInput(transform.Parameters[0].Source)
		if err != nil {
			return Outcome{}, err
		}
		if _, err := io.ReadAll(reader); err != nil {
			return Outcome{}, err
		}
		return successfulCommitOutcome(), nil
	}))
	first := openWorkspace(t, host)
	second := openWorkspace(t, host)
	source := &byteSource{data: []byte("secret")}
	handle, err := first.RegisterInput(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	action := TransformAction{
		BaseCommit: digest.FromString("base"), Transform: TransformRef{Builtin: testType("Normalize")},
		Inputs:     []PinnedInput{{Role: testRole(), UID: testResourceID, Sealed: testSealed("input"), Payload: "content"}},
		Parameters: []TransformParameter{{Name: "value", Source: handle}},
		Outputs:    []TransformOutput{testTransformOutput()},
	}
	if _, err := second.Start(context.Background(), action); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("cross-session handle error = %v", err)
	}
	id, err := first.Start(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Wait(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if source.opens.Load() != 1 {
		t.Fatalf("source opens = %d", source.opens.Load())
	}
	if _, err := first.Start(context.Background(), action); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("reused handle error = %v", err)
	}
}

func TestExpiredHandleFailsClosed(t *testing.T) {
	now := time.Unix(1_000, 0)
	executor := executorFunc(func(context.Context, Execution, Action) (Outcome, error) { return successfulCommitOutcome(), nil })
	host, err := newHost(executor, queryExecutorStub{}, func() time.Time { return now }, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	workspace := openWorkspace(t, host)
	handle, err := workspace.RegisterInput(context.Background(), &byteSource{})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	action := TransformAction{
		BaseCommit: digest.FromString("base"), Transform: TransformRef{Builtin: testType("Normalize")},
		Inputs:     []PinnedInput{{Role: testRole(), UID: testResourceID, Sealed: testSealed("input"), Payload: "content"}},
		Parameters: []TransformParameter{{Name: "value", Source: handle}},
		Outputs:    []TransformOutput{testTransformOutput()},
	}
	if _, err := workspace.Start(context.Background(), action); !errors.Is(err, ErrHandleExpired) {
		t.Fatalf("expired handle error = %v", err)
	}
}

func TestHandleRegistrationIsBounded(t *testing.T) {
	host := newTestHost(t, executorFunc(func(context.Context, Execution, Action) (Outcome, error) {
		return successfulCommitOutcome(), nil
	}))
	workspace := openWorkspace(t, host)
	for index := 0; index < MaxHandlesPerWorkspace; index++ {
		if _, err := workspace.RegisterInput(context.Background(), &byteSource{}); err != nil {
			t.Fatalf("register handle %d: %v", index, err)
		}
	}
	if _, err := workspace.RegisterInput(context.Background(), &byteSource{}); !errors.Is(err, ErrHandleLimit) {
		t.Fatalf("handle limit error = %v", err)
	}
}

func TestProgressRingIsBoundedAndCursorAware(t *testing.T) {
	host := newTestHost(t, executorFunc(func(_ context.Context, execution Execution, _ Action) (Outcome, error) {
		for index := uint64(0); index < MaxProgressEvents+17; index++ {
			if err := execution.Report(PhasePublishing, ProgressUnitItems, index, MaxProgressEvents+17); err != nil {
				return Outcome{}, err
			}
		}
		return successfulCommitOutcome(), nil
	}))
	workspace := openWorkspace(t, host)
	id, err := workspace.Start(context.Background(), validRestoreAction())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	snapshot, err := workspace.Poll(context.Background(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Events) != MaxProgressEvents || !snapshot.Truncated {
		t.Fatalf("events=%d truncated=%v", len(snapshot.Events), snapshot.Truncated)
	}
	if snapshot.Events[len(snapshot.Events)-1].Sequence != snapshot.NextCursor {
		t.Fatal("cursor does not match latest event")
	}
	empty, err := workspace.Poll(context.Background(), id, snapshot.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Events) != 0 || empty.Truncated {
		t.Fatalf("unexpected repeated events: %#v", empty)
	}
	if _, err := workspace.Poll(context.Background(), id, snapshot.NextCursor+1); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("future cursor error = %v", err)
	}
}

func TestInvalidProgressFailsOperation(t *testing.T) {
	host := newTestHost(t, executorFunc(func(_ context.Context, execution Execution, _ Action) (Outcome, error) {
		return Outcome{}, execution.Report(PhasePublishing, ProgressUnitItems, 2, 1)
	}))
	workspace := openWorkspace(t, host)
	id, err := workspace.Start(context.Background(), validRestoreAction())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); !errors.Is(err, ErrInvalidProgress) {
		t.Fatalf("invalid progress result = %v", err)
	}
}

func TestCancelIsIdempotentAndWaitsForExecutor(t *testing.T) {
	started := make(chan struct{})
	exited := make(chan struct{})
	host := newTestHost(t, executorFunc(func(ctx context.Context, _ Execution, _ Action) (Outcome, error) {
		close(started)
		<-ctx.Done()
		close(exited)
		return Outcome{}, ctx.Err()
	}))
	workspace := openWorkspace(t, host)
	id, err := workspace.Start(context.Background(), validRestoreAction())
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if err := workspace.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v", err)
	}
	<-exited
	snapshot, err := workspace.Poll(context.Background(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != StateCanceled || snapshot.Failure != nil {
		t.Fatalf("canceled snapshot = %#v", snapshot)
	}
}

func TestCancellationWinsOverLateExecutorSuccess(t *testing.T) {
	started := make(chan struct{})
	output := &memoryOutput{}
	host := newTestHost(t, executorFunc(func(ctx context.Context, execution Execution, action Action) (Outcome, error) {
		materialize := action.(MaterializeAction)
		writer, err := execution.OpenOutput(materialize.Destination)
		if err != nil {
			return Outcome{}, err
		}
		if _, err := writer.Write([]byte("secret")); err != nil {
			return Outcome{}, err
		}
		close(started)
		<-ctx.Done()
		return Outcome{Materialize: &MaterializeResult{Objects: 1, Bytes: 6}}, nil
	}))
	workspace := openWorkspace(t, host)
	handle, err := workspace.RegisterOutput(context.Background(), memoryTarget{output: output})
	if err != nil {
		t.Fatal(err)
	}
	id, err := workspace.Start(context.Background(), MaterializeAction{
		AtCommit: digest.FromString("commit"), Target: testResourceID, Format: testType("Raw"), Destination: handle,
	})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if err := workspace.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v", err)
	}
	if output.commits.Load() != 0 || output.aborts.Load() != 1 {
		t.Fatalf("commits=%d aborts=%d", output.commits.Load(), output.aborts.Load())
	}
}

func TestPublishedCommitWinsCancellationAtVisibilityPoint(t *testing.T) {
	started := make(chan struct{})
	host := newTestHost(t, executorFunc(func(ctx context.Context, _ Execution, _ Action) (Outcome, error) {
		close(started)
		<-ctx.Done()
		// A Commit result means the remote visibility point was already
		// crossed. Reporting cancellation now would invite an unsafe retry.
		return successfulCommitOutcome(), nil
	}))
	workspace := openWorkspace(t, host)
	id, err := workspace.Start(context.Background(), validRestoreAction())
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if err := workspace.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	outcome, err := workspace.Wait(context.Background(), id)
	if err != nil || outcome.Commit == nil {
		t.Fatalf("published Wait = %#v, %v", outcome, err)
	}
	snapshot, err := workspace.Poll(context.Background(), id, 0)
	if err != nil || snapshot.State != StateSucceeded {
		t.Fatalf("published snapshot = %#v, %v", snapshot, err)
	}
}

func TestOperationIDsCannotCrossWorkspace(t *testing.T) {
	host := newTestHost(t, executorFunc(func(context.Context, Execution, Action) (Outcome, error) { return successfulCommitOutcome(), nil }))
	first := openWorkspace(t, host)
	second := openWorkspace(t, host)
	id, err := first.Start(context.Background(), validRestoreAction())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Wait(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Poll(context.Background(), id, 0); !errors.Is(err, ErrUnknownOperation) {
		t.Fatalf("cross-workspace poll error = %v", err)
	}
	if err := second.Cancel(context.Background(), id); !errors.Is(err, ErrUnknownOperation) {
		t.Fatalf("cross-workspace cancel error = %v", err)
	}
}

func TestOutputMustBeOpenedAndCommitted(t *testing.T) {
	output := &memoryOutput{}
	host := newTestHost(t, executorFunc(func(context.Context, Execution, Action) (Outcome, error) {
		return Outcome{Materialize: &MaterializeResult{Objects: 1, Bytes: 5}}, nil
	}))
	workspace := openWorkspace(t, host)
	handle, err := workspace.RegisterOutput(context.Background(), memoryTarget{output: output})
	if err != nil {
		t.Fatal(err)
	}
	action := MaterializeAction{AtCommit: digest.FromString("commit"), Target: testResourceID, Format: testType("DotEnv"), Destination: handle}
	id, err := workspace.Start(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); !errors.Is(err, ErrHandleNotConsumed) {
		t.Fatalf("unconsumed output error = %v", err)
	}
	if output.aborts.Load() != 0 {
		t.Fatalf("unopened target aborts = %d", output.aborts.Load())
	}
	if _, err := workspace.Start(context.Background(), action); !errors.Is(err, ErrInvalidHandle) {
		t.Fatalf("output handle reuse error = %v", err)
	}
}

func TestMaterializeCommitsTransactionalOutput(t *testing.T) {
	output := &memoryOutput{}
	host := newTestHost(t, executorFunc(func(_ context.Context, execution Execution, action Action) (Outcome, error) {
		materialize := action.(MaterializeAction)
		writer, err := execution.OpenOutput(materialize.Destination)
		if err != nil {
			return Outcome{}, err
		}
		if _, err := writer.Write([]byte("value")); err != nil {
			return Outcome{}, err
		}
		return Outcome{Materialize: &MaterializeResult{Objects: 1, Bytes: 5}}, nil
	}))
	workspace := openWorkspace(t, host)
	handle, err := workspace.RegisterOutput(context.Background(), memoryTarget{output: output})
	if err != nil {
		t.Fatal(err)
	}
	id, err := workspace.Start(context.Background(), MaterializeAction{AtCommit: digest.FromString("commit"), Target: testResourceID, Format: testType("DotEnv"), Destination: handle})
	if err != nil {
		t.Fatal(err)
	}
	result, err := workspace.Wait(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if result.Materialize == nil || output.String() != "value" || output.commits.Load() != 1 || output.aborts.Load() != 0 {
		t.Fatalf("result=%#v output=%q commits=%d aborts=%d", result, output.String(), output.commits.Load(), output.aborts.Load())
	}
}

func TestFailedMaterializeAbortsTransactionalOutput(t *testing.T) {
	output := &memoryOutput{}
	host := newTestHost(t, executorFunc(func(_ context.Context, execution Execution, action Action) (Outcome, error) {
		materialize := action.(MaterializeAction)
		writer, err := execution.OpenOutput(materialize.Destination)
		if err != nil {
			return Outcome{}, err
		}
		if _, err := writer.Write([]byte("partial")); err != nil {
			return Outcome{}, err
		}
		return Outcome{}, errors.New("materializer failed")
	}))
	workspace := openWorkspace(t, host)
	handle, err := workspace.RegisterOutput(context.Background(), memoryTarget{output: output})
	if err != nil {
		t.Fatal(err)
	}
	id, err := workspace.Start(context.Background(), MaterializeAction{AtCommit: digest.FromString("commit"), Target: testResourceID, Format: testType("DotEnv"), Destination: handle})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); err == nil {
		t.Fatal("failed materializer returned nil error")
	}
	if output.commits.Load() != 0 || output.aborts.Load() != 1 {
		t.Fatalf("commits=%d aborts=%d", output.commits.Load(), output.aborts.Load())
	}
}

func TestFinalizeRunsAfterOutputCommitAndCannotReuseScope(t *testing.T) {
	output := &memoryOutput{}
	finalized := atomic.Bool{}
	executor := lifecycleExecutor{
		execute: func(_ context.Context, execution Execution, action Action) (Outcome, error) {
			writer, err := execution.OpenOutput(action.(MaterializeAction).Destination)
			if err != nil {
				return Outcome{}, err
			}
			if _, err := writer.Write([]byte("secret")); err != nil {
				return Outcome{}, err
			}
			return Outcome{Materialize: &MaterializeResult{Objects: 1, Bytes: 6}}, nil
		},
		finalize: func(ctx context.Context, execution Execution, action Action, outcome Outcome, executeErr error) error {
			if executeErr != nil {
				t.Fatalf("Finalize execute error = %v", executeErr)
			}
			if _, hasDeadline := ctx.Deadline(); !hasDeadline {
				t.Fatal("Finalize context is not bounded")
			}
			if output.commits.Load() != 1 || output.aborts.Load() != 0 {
				t.Fatalf("Finalize observed commits=%d aborts=%d", output.commits.Load(), output.aborts.Load())
			}
			if outcome.Materialize == nil {
				t.Fatalf("Finalize outcome = %#v", outcome)
			}
			if _, err := execution.OpenOutput(action.(MaterializeAction).Destination); !errors.Is(err, ErrHandleConsumed) {
				t.Fatalf("Finalize reopened output: %v", err)
			}
			if err := execution.Report(PhaseMaterializing, ProgressUnitItems, 1, 1); !errors.Is(err, ErrInvalidProgress) {
				t.Fatalf("Finalize reported progress: %v", err)
			}
			finalized.Store(true)
			return nil
		},
	}
	host := newTestHost(t, executor)
	workspace := openWorkspace(t, host)
	handle, err := workspace.RegisterOutput(context.Background(), memoryTarget{output: output})
	if err != nil {
		t.Fatal(err)
	}
	id, err := workspace.Start(context.Background(), MaterializeAction{
		AtCommit: digest.FromString("commit"), Target: testResourceID, Format: testType("DotEnv"), Destination: handle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if !finalized.Load() {
		t.Fatal("Finalize was not called")
	}
}

func TestFinalizeFailureLeavesCommittedOutputButFailsOperation(t *testing.T) {
	output := &memoryOutput{}
	finalizeFailure := errors.New("terminal audit failed")
	executor := lifecycleExecutor{
		execute: func(_ context.Context, execution Execution, action Action) (Outcome, error) {
			writer, err := execution.OpenOutput(action.(MaterializeAction).Destination)
			if err != nil {
				return Outcome{}, err
			}
			if _, err := writer.Write([]byte("secret")); err != nil {
				return Outcome{}, err
			}
			return Outcome{Materialize: &MaterializeResult{Objects: 1, Bytes: 6}}, nil
		},
		finalize: func(context.Context, Execution, Action, Outcome, error) error {
			if output.commits.Load() != 1 {
				t.Fatalf("output was not committed before Finalize")
			}
			return finalizeFailure
		},
	}
	host := newTestHost(t, executor)
	workspace := openWorkspace(t, host)
	handle, err := workspace.RegisterOutput(context.Background(), memoryTarget{output: output})
	if err != nil {
		t.Fatal(err)
	}
	id, err := workspace.Start(context.Background(), MaterializeAction{
		AtCommit: digest.FromString("commit"), Target: testResourceID, Format: testType("DotEnv"), Destination: handle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); err == nil {
		t.Fatal("Finalize failure did not fail operation")
	}
	snapshot, err := workspace.Poll(context.Background(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != StateFailed || output.commits.Load() != 1 || output.aborts.Load() != 0 {
		t.Fatalf("state=%s commits=%d aborts=%d", snapshot.State, output.commits.Load(), output.aborts.Load())
	}
}

func TestFinalizeUsesIndependentBoundedContextAfterCancellation(t *testing.T) {
	started := make(chan struct{})
	type observation struct {
		contextErr      error
		hasDeadline     bool
		executeCanceled bool
	}
	observed := make(chan observation, 1)
	executor := lifecycleExecutor{
		execute: func(ctx context.Context, _ Execution, _ Action) (Outcome, error) {
			close(started)
			<-ctx.Done()
			return Outcome{}, ctx.Err()
		},
		finalize: func(ctx context.Context, _ Execution, _ Action, _ Outcome, executeErr error) error {
			_, hasDeadline := ctx.Deadline()
			observed <- observation{
				contextErr: ctx.Err(), hasDeadline: hasDeadline,
				executeCanceled: errors.Is(executeErr, context.Canceled),
			}
			return nil
		},
	}
	host := newTestHost(t, executor)
	workspace := openWorkspace(t, host)
	id, err := workspace.Start(context.Background(), validRestoreAction())
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if err := workspace.Cancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v", err)
	}
	result := <-observed
	if result.contextErr != nil || !result.hasDeadline || !result.executeCanceled {
		t.Fatalf("Finalize observation = %#v", result)
	}
}

func TestConflictAllowsUnopenedInputAndReachesFinalize(t *testing.T) {
	source := &byteSource{data: []byte("unused")}
	finalized := atomic.Bool{}
	conflict := ConflictSummary{
		ID: testConflictID, Target: testResourceID, Schema: testType("Opaque"), Kind: ConflictConcurrentChange,
		Base: digest.FromString("base"), Ours: digest.FromString("ours"), Theirs: digest.FromString("theirs"),
	}
	executor := lifecycleExecutor{
		execute: func(context.Context, Execution, Action) (Outcome, error) {
			return Outcome{Conflict: &ConflictResult{Conflicts: []ConflictSummary{conflict}}}, nil
		},
		finalize: func(_ context.Context, _ Execution, _ Action, outcome Outcome, executeErr error) error {
			if executeErr != nil || outcome.Conflict == nil || len(outcome.Conflict.Conflicts) != 1 {
				t.Fatalf("Finalize conflict=%#v error=%v", outcome, executeErr)
			}
			finalized.Store(true)
			return nil
		},
	}
	host := newTestHost(t, executor)
	workspace := openWorkspace(t, host)
	handle, err := workspace.RegisterInput(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	action := TransformAction{
		BaseCommit: digest.FromString("base"), Transform: TransformRef{Builtin: testType("Normalize")},
		Inputs:     []PinnedInput{{Role: testRole(), UID: testResourceID, Sealed: testSealed("input"), Payload: "content"}},
		Parameters: []TransformParameter{{Name: "value", Source: handle}},
		Outputs:    []TransformOutput{testTransformOutput()},
	}
	id, err := workspace.Start(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	result, err := workspace.Wait(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if result.Conflict == nil || source.opens.Load() != 0 || !finalized.Load() {
		t.Fatalf("result=%#v opens=%d finalized=%v", result, source.opens.Load(), finalized.Load())
	}
	snapshot, err := workspace.Poll(context.Background(), id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != StateConflicted {
		t.Fatalf("state = %s", snapshot.State)
	}
}

func TestConflictedScopeAbortsOpenedOutput(t *testing.T) {
	output := &memoryOutput{}
	scope := &executionScope{
		inputs: map[InputHandle]*claimedInput{},
		outputs: map[OutputHandle]*claimedOutput{
			testOutputHandle: {opened: true, output: &trackedOutput{output: output}},
		},
	}
	if err := scope.finish(scopeConflicted); err != nil {
		t.Fatal(err)
	}
	if output.commits.Load() != 0 || output.aborts.Load() != 1 {
		t.Fatalf("commits=%d aborts=%d", output.commits.Load(), output.aborts.Load())
	}
}

func TestCloseCancelsOperationsAndInvalidatesHandles(t *testing.T) {
	started := make(chan struct{})
	host := newTestHost(t, executorFunc(func(ctx context.Context, _ Execution, _ Action) (Outcome, error) {
		close(started)
		<-ctx.Done()
		return Outcome{}, ctx.Err()
	}))
	workspace := openWorkspace(t, host)
	if _, err := workspace.RegisterInput(context.Background(), &byteSource{}); err != nil {
		t.Fatal(err)
	}
	id, err := workspace.Start(context.Background(), validRestoreAction())
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if err := workspace.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := workspace.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Wait(context.Background(), id); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed operation error = %v", err)
	}
	if _, err := workspace.RegisterInput(context.Background(), &byteSource{}); !errors.Is(err, ErrWorkspaceClosed) {
		t.Fatalf("register after close = %v", err)
	}
	if _, err := workspace.Start(context.Background(), validRestoreAction()); !errors.Is(err, ErrWorkspaceClosed) {
		t.Fatalf("start after close = %v", err)
	}
}

func TestHostCloseDrainsAllWorkspaces(t *testing.T) {
	started := make(chan struct{}, 2)
	host := newTestHost(t, executorFunc(func(ctx context.Context, _ Execution, _ Action) (Outcome, error) {
		started <- struct{}{}
		<-ctx.Done()
		return Outcome{}, ctx.Err()
	}))
	first := openWorkspace(t, host)
	second := openWorkspace(t, host)
	for _, workspace := range []*Workspace{first, second} {
		if _, err := workspace.Start(context.Background(), validRestoreAction()); err != nil {
			t.Fatal(err)
		}
	}
	<-started
	<-started
	if err := host.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := host.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, workspace := range []*Workspace{first, second} {
		if _, err := workspace.Start(context.Background(), validRestoreAction()); !errors.Is(err, ErrWorkspaceClosed) {
			t.Fatalf("start after host close = %v", err)
		}
	}
}

func TestCompletedOperationsDoNotExhaustWorkspaceLifetime(t *testing.T) {
	host := newTestHost(t, executorFunc(func(context.Context, Execution, Action) (Outcome, error) {
		return successfulCommitOutcome(), nil
	}))
	workspace := openWorkspace(t, host)
	var first OperationID
	for index := 0; index <= MaxOperationsPerWorkspace; index++ {
		id, err := workspace.Start(context.Background(), validRestoreAction())
		if err != nil {
			t.Fatalf("Start %d: %v", index, err)
		}
		if index == 0 {
			first = id
		}
		if _, err := workspace.Wait(context.Background(), id); err != nil {
			t.Fatalf("Wait %d: %v", index, err)
		}
	}
	if _, err := workspace.Poll(context.Background(), first, 0); !errors.Is(err, ErrUnknownOperation) {
		t.Fatalf("oldest retained operation = %v", err)
	}
}

func TestConcurrentReportingPollingAndWaiting(t *testing.T) {
	host := newTestHost(t, executorFunc(func(_ context.Context, execution Execution, _ Action) (Outcome, error) {
		var reports sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			reports.Add(1)
			go func() {
				defer reports.Done()
				for index := uint64(0); index < 64; index++ {
					if err := execution.Report(PhaseDiscovering, ProgressUnitItems, index, 64); err != nil {
						return
					}
				}
			}()
		}
		reports.Wait()
		return successfulCommitOutcome(), nil
	}))
	workspace := openWorkspace(t, host)
	const operationCount = 32
	ids := make([]OperationID, operationCount)
	for index := range ids {
		id, err := workspace.Start(context.Background(), validRestoreAction())
		if err != nil {
			t.Fatal(err)
		}
		ids[index] = id
	}
	var waiters sync.WaitGroup
	for _, id := range ids {
		id := id
		waiters.Add(2)
		go func() {
			defer waiters.Done()
			if _, err := workspace.Wait(context.Background(), id); err != nil {
				t.Errorf("wait: %v", err)
			}
		}()
		go func() {
			defer waiters.Done()
			cursor := uint64(0)
			for {
				snapshot, err := workspace.Poll(context.Background(), id, cursor)
				if err != nil {
					t.Errorf("poll: %v", err)
					return
				}
				cursor = snapshot.NextCursor
				if isTerminal(snapshot.State) {
					return
				}
				runtime.Gosched()
			}
		}()
	}
	waiters.Wait()
}

func TestOpenWorkspaceRejectsLegacyWithoutChangingRootMode(t *testing.T) {
	host := newTestHost(t, executorFunc(func(context.Context, Execution, Action) (Outcome, error) { return Outcome{}, nil }))
	root := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "enbu.toml"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := host.OpenWorkspace(context.Background(), OpenWorkspaceRequest{WorkspaceID: testWorkspaceID, Root: root, ConfigRevision: digest.FromString("config")})
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("legacy error = %v", err)
	}
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(root)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("workspace root mode changed to %o", info.Mode().Perm())
		}
	}
}

package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	MaxProgressEvents  = 128
	MaxResultChanges   = 10_000
	MaxResultConflicts = 10_000
)

type ProgressPhase string

const (
	PhaseValidating    ProgressPhase = "validating"
	PhaseDiscovering   ProgressPhase = "discovering"
	PhaseDecrypting    ProgressPhase = "decrypting"
	PhaseTransforming  ProgressPhase = "transforming"
	PhasePolicy        ProgressPhase = "policy"
	PhaseSealing       ProgressPhase = "sealing"
	PhasePublishing    ProgressPhase = "publishing"
	PhaseMaterializing ProgressPhase = "materializing"
)

func (phase ProgressPhase) valid() bool {
	switch phase {
	case PhaseValidating, PhaseDiscovering, PhaseDecrypting, PhaseTransforming, PhasePolicy, PhaseSealing, PhasePublishing, PhaseMaterializing:
		return true
	default:
		return false
	}
}

type ProgressUnit string

const (
	ProgressUnitNone  ProgressUnit = "none"
	ProgressUnitItems ProgressUnit = "items"
	ProgressUnitBytes ProgressUnit = "bytes"
)

func (unit ProgressUnit) valid() bool {
	return unit == ProgressUnitNone || unit == ProgressUnitItems || unit == ProgressUnitBytes
}

type ProgressEvent struct {
	OperationID OperationID   `json:"operation_id"`
	Sequence    uint64        `json:"sequence"`
	Phase       ProgressPhase `json:"phase"`
	Unit        ProgressUnit  `json:"unit"`
	Completed   uint64        `json:"completed"`
	Total       uint64        `json:"total"`
}

type OperationState string

const (
	StateQueued     OperationState = "queued"
	StateRunning    OperationState = "running"
	StateSucceeded  OperationState = "succeeded"
	StateConflicted OperationState = "conflicted"
	StateFailed     OperationState = "failed"
	StateCanceled   OperationState = "canceled"
)

type ResourceChangeKind string

const (
	ResourceCreated ResourceChangeKind = "created"
	ResourceUpdated ResourceChangeKind = "updated"
	ResourceDeleted ResourceChangeKind = "deleted"
)

type ResourceChange struct {
	UID    artifact.UUID      `json:"uid"`
	Kind   ResourceChangeKind `json:"kind"`
	Before digest.Digest      `json:"before,omitempty"`
	After  digest.Digest      `json:"after,omitempty"`
}

type CommitResult struct {
	Commit  digest.Digest      `json:"commit"`
	Root    artifact.SealedRef `json:"root"`
	Changes []ResourceChange   `json:"changes"`
}

type InitializeResult struct {
	WorkspaceID artifact.UUID      `json:"workspace_id"`
	Commit      digest.Digest      `json:"commit"`
	Root        artifact.SealedRef `json:"root"`
}

type MaterializeResult struct {
	Objects uint64 `json:"objects"`
	Bytes   uint64 `json:"bytes"`
}

type ConflictKind string

const (
	ConflictConcurrentChange ConflictKind = "concurrent_change"
	ConflictUpdateDelete     ConflictKind = "update_delete"
	ConflictAccess           ConflictKind = "access"
	ConflictPolicy           ConflictKind = "policy"
)

type ConflictSummary struct {
	ID     artifact.UUID    `json:"id"`
	Target artifact.UUID    `json:"target"`
	Schema artifact.TypeRef `json:"schema"`
	Kind   ConflictKind     `json:"kind"`
	Base   digest.Digest    `json:"base,omitempty"`
	Ours   digest.Digest    `json:"ours,omitempty"`
	Theirs digest.Digest    `json:"theirs,omitempty"`
}

type ConflictResult struct {
	Conflicts []ConflictSummary `json:"conflicts"`
}

// Outcome is an exactly-one, payload-free result union.
type Outcome struct {
	Initialize  *InitializeResult  `json:"initialize,omitempty"`
	Commit      *CommitResult      `json:"commit,omitempty"`
	Materialize *MaterializeResult `json:"materialize,omitempty"`
	Conflict    *ConflictResult    `json:"conflict,omitempty"`
}

type OperationSnapshot struct {
	ID         OperationID     `json:"operation_id"`
	Kind       ActionKind      `json:"kind"`
	State      OperationState  `json:"state"`
	Events     []ProgressEvent `json:"events,omitempty"`
	NextCursor uint64          `json:"next_cursor"`
	Truncated  bool            `json:"truncated"`
	Result     *Outcome        `json:"result,omitempty"`
	Failure    *apperr.Payload `json:"failure,omitempty"`
}

type operationState struct {
	id     OperationID
	kind   ActionKind
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once

	mu              sync.Mutex
	state           OperationState
	events          []ProgressEvent
	nextSequence    uint64
	cancelRequested bool
	commitStarted   bool
	outcome         Outcome
	err             error
}

func newOperationState(id OperationID, kind ActionKind, cancel context.CancelFunc) *operationState {
	return &operationState{id: id, kind: kind, cancel: cancel, done: make(chan struct{}), state: StateQueued}
}

func (operation *operationState) setRunning() {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if operation.state == StateQueued {
		operation.state = StateRunning
	}
}

func (operation *operationState) report(phase ProgressPhase, unit ProgressUnit, completed, total uint64) error {
	if !phase.valid() || !unit.valid() || (total != 0 && completed > total) || (unit == ProgressUnitNone && (completed != 0 || total != 0)) {
		return ErrInvalidProgress
	}
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if isTerminal(operation.state) {
		return ErrInvalidProgress
	}
	operation.nextSequence++
	event := ProgressEvent{OperationID: operation.id, Sequence: operation.nextSequence, Phase: phase, Unit: unit, Completed: completed, Total: total}
	if len(operation.events) == MaxProgressEvents {
		copy(operation.events, operation.events[1:])
		operation.events[len(operation.events)-1] = event
	} else {
		operation.events = append(operation.events, event)
	}
	return nil
}

func (operation *operationState) requestCancel() {
	operation.mu.Lock()
	if operation.commitStarted {
		operation.mu.Unlock()
		return
	}
	operation.cancelRequested = true
	terminal := isTerminal(operation.state)
	operation.mu.Unlock()
	if !terminal {
		operation.cancel()
	}
}

func (operation *operationState) beginCommit(ctx context.Context, irreversible bool) bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if isTerminal(operation.state) {
		return false
	}
	if !irreversible {
		if operation.cancelRequested || ctx.Err() != nil {
			return false
		}
	}
	operation.commitStarted = true
	return true
}

func (operation *operationState) terminal() bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	return isTerminal(operation.state)
}

func (operation *operationState) finish(ctxErr error, outcome Outcome, executeErr error, finalizeFailed bool) {
	operation.once.Do(func() {
		operation.mu.Lock()
		defer operation.mu.Unlock()
		switch {
		case finalizeFailed:
			operation.state = StateFailed
			operation.err = apperr.Normalize(executeErr)
		case !operation.commitStarted && (operation.cancelRequested || ctxErr != nil || errors.Is(executeErr, context.Canceled) || errors.Is(executeErr, context.DeadlineExceeded)):
			operation.state = StateCanceled
			if ctxErr != nil {
				operation.err = ctxErr
			} else if executeErr != nil {
				operation.err = executeErr
			} else {
				operation.err = context.Canceled
			}
		case executeErr != nil:
			operation.state = StateFailed
			operation.err = apperr.Normalize(executeErr)
		case outcome.Conflict != nil:
			operation.state = StateConflicted
			operation.outcome = cloneOutcome(outcome)
		default:
			operation.state = StateSucceeded
			operation.outcome = cloneOutcome(outcome)
		}
		close(operation.done)
	})
}

func isTerminal(state OperationState) bool {
	return state == StateSucceeded || state == StateConflicted || state == StateFailed || state == StateCanceled
}

func (host *Host) runOperation(ctx context.Context, stopCaller func() bool, operation *operationState, scope *executionScope, action Action) {
	operation.setRunning()
	_ = operation.report(PhaseValidating, ProgressUnitNone, 0, 0)
	var outcome Outcome
	var executeErr error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				executeErr = fmt.Errorf("executor panic: %v", recovered)
			}
		}()
		outcome, executeErr = host.executor.Execute(ctx, scope, action)
	}()
	if executeErr == nil {
		if err := outcome.validate(action.Kind()); err != nil {
			executeErr = err
		} else {
			outcome = cloneOutcome(outcome)
		}
	}
	disposition := scopeFailed
	if executeErr == nil {
		irreversible := outcome.Initialize != nil || outcome.Commit != nil
		if outcome.Conflict != nil {
			disposition = scopeConflicted
		} else if operation.beginCommit(ctx, irreversible) {
			disposition = scopeSucceeded
		} else {
			executeErr = context.Canceled
		}
	}
	if cleanupErr := scope.finish(disposition); cleanupErr != nil {
		executeErr = errors.Join(executeErr, cleanupErr)
	}
	finalizeContext, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), DefaultFinalizeTimeout)
	finalizeErr := callFinalize(host.executor, finalizeContext, scope, action, cloneOutcome(outcome), executeErr)
	cancelFinalize()
	finalizeFailed := finalizeErr != nil
	if finalizeErr != nil {
		executeErr = errors.Join(executeErr, finalizeErr)
	}
	stopCaller()
	ctxErr := ctx.Err()
	operation.finish(ctxErr, outcome, executeErr, finalizeFailed)
	scope.workspace.recordCompleted(operation.id, operation)
	operation.cancel()
}

func callFinalize(executor Executor, ctx context.Context, execution Execution, action Action, outcome Outcome, executeErr error) (finalizeErr error) {
	defer func() {
		if recover() != nil {
			finalizeErr = errors.New("executor finalize panic")
		}
	}()
	return executor.Finalize(ctx, execution, action, outcome, executeErr)
}

func (workspace *Workspace) Poll(ctx context.Context, id OperationID, after uint64) (OperationSnapshot, error) {
	if ctx == nil {
		return OperationSnapshot{}, fmt.Errorf("%w: nil context", ErrUnknownOperation)
	}
	if err := ctx.Err(); err != nil {
		return OperationSnapshot{}, err
	}
	operation, err := workspace.operation(id)
	if err != nil {
		return OperationSnapshot{}, err
	}
	operation.mu.Lock()
	defer operation.mu.Unlock()
	if after > operation.nextSequence {
		return OperationSnapshot{}, ErrInvalidCursor
	}
	snapshot := OperationSnapshot{ID: operation.id, Kind: operation.kind, State: operation.state, NextCursor: operation.nextSequence}
	if len(operation.events) != 0 {
		oldest := operation.events[0].Sequence
		snapshot.Truncated = after < oldest-1
		for _, event := range operation.events {
			if event.Sequence > after {
				snapshot.Events = append(snapshot.Events, event)
			}
		}
	}
	if isTerminal(operation.state) {
		if operation.err != nil && operation.state == StateFailed {
			payload := apperr.PayloadOf(operation.err)
			snapshot.Failure = &payload
		}
		if operation.state == StateSucceeded || operation.state == StateConflicted {
			result := cloneOutcome(operation.outcome)
			snapshot.Result = &result
		}
	}
	return snapshot, nil
}

func (workspace *Workspace) Wait(ctx context.Context, id OperationID) (Outcome, error) {
	if ctx == nil {
		return Outcome{}, fmt.Errorf("%w: nil context", ErrUnknownOperation)
	}
	operation, err := workspace.operation(id)
	if err != nil {
		return Outcome{}, err
	}
	select {
	case <-operation.done:
		operation.mu.Lock()
		defer operation.mu.Unlock()
		return cloneOutcome(operation.outcome), operation.err
	case <-ctx.Done():
		return Outcome{}, ctx.Err()
	}
}

func (workspace *Workspace) Cancel(ctx context.Context, id OperationID) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrUnknownOperation)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	operation, err := workspace.operation(id)
	if err != nil {
		return err
	}
	operation.requestCancel()
	return nil
}

func (workspace *Workspace) operation(id OperationID) (*operationState, error) {
	if err := id.validate(); err != nil {
		return nil, ErrUnknownOperation
	}
	state, err := workspace.validState()
	if err != nil {
		return nil, err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	operation, exists := state.operations[id]
	if !exists {
		return nil, ErrUnknownOperation
	}
	return operation, nil
}

type executionScope struct {
	ctx       context.Context
	workspace *workspaceState
	operation *operationState

	mu       sync.Mutex
	terminal bool
	inputs   map[InputHandle]*claimedInput
	outputs  map[OutputHandle]*claimedOutput
}

type claimedInput struct {
	source InputSource
	opened bool
	reader io.ReadCloser
}

type claimedOutput struct {
	target OutputTarget
	opened bool
	output *trackedOutput
}

func newExecutionScope(ctx context.Context, workspace *workspaceState, operation *operationState, inputs map[InputHandle]InputSource, outputs map[OutputHandle]OutputTarget) *executionScope {
	scope := &executionScope{ctx: ctx, workspace: workspace, operation: operation, inputs: make(map[InputHandle]*claimedInput, len(inputs)), outputs: make(map[OutputHandle]*claimedOutput, len(outputs))}
	for handle, source := range inputs {
		scope.inputs[handle] = &claimedInput{source: source}
	}
	for handle, target := range outputs {
		scope.outputs[handle] = &claimedOutput{target: target}
	}
	return scope
}

func (scope *executionScope) OperationID() artifact.UUID    { return artifact.UUID(scope.operation.id) }
func (scope *executionScope) WorkspaceID() artifact.UUID    { return scope.workspace.workspaceID }
func (scope *executionScope) Root() string                  { return scope.workspace.root }
func (scope *executionScope) ConfigRevision() digest.Digest { return scope.workspace.configRevision }

func (scope *executionScope) OpenInput(handle InputHandle) (io.ReadCloser, error) {
	if err := scope.ctx.Err(); err != nil {
		return nil, err
	}
	scope.mu.Lock()
	if scope.terminal {
		scope.mu.Unlock()
		return nil, ErrHandleConsumed
	}
	claimed, exists := scope.inputs[handle]
	if !exists {
		scope.mu.Unlock()
		return nil, ErrInvalidHandle
	}
	if claimed.opened {
		scope.mu.Unlock()
		return nil, ErrHandleConsumed
	}
	claimed.opened = true
	reader, err := claimed.source.Open(scope.ctx)
	if err != nil {
		scope.mu.Unlock()
		return nil, err
	}
	if isNilInterface(reader) {
		scope.mu.Unlock()
		return nil, fmt.Errorf("%w: input source returned nil", ErrInvalidHandle)
	}
	claimed.reader = reader
	scope.mu.Unlock()
	return reader, nil
}

func (scope *executionScope) OpenOutput(handle OutputHandle) (io.Writer, error) {
	if err := scope.ctx.Err(); err != nil {
		return nil, err
	}
	scope.mu.Lock()
	if scope.terminal {
		scope.mu.Unlock()
		return nil, ErrHandleConsumed
	}
	claimed, exists := scope.outputs[handle]
	if !exists {
		scope.mu.Unlock()
		return nil, ErrInvalidHandle
	}
	if claimed.opened {
		scope.mu.Unlock()
		return nil, ErrHandleConsumed
	}
	claimed.opened = true
	output, err := claimed.target.Open(scope.ctx)
	if err != nil {
		scope.mu.Unlock()
		return nil, err
	}
	if isNilInterface(output) {
		scope.mu.Unlock()
		return nil, fmt.Errorf("%w: output target returned nil", ErrInvalidHandle)
	}
	tracked := &trackedOutput{output: output}
	claimed.output = tracked
	scope.mu.Unlock()
	return tracked, nil
}

func (scope *executionScope) Report(phase ProgressPhase, unit ProgressUnit, completed, total uint64) error {
	if err := scope.ctx.Err(); err != nil {
		return err
	}
	scope.mu.Lock()
	terminal := scope.terminal
	scope.mu.Unlock()
	if terminal {
		return ErrInvalidProgress
	}
	return scope.operation.report(phase, unit, completed, total)
}

type scopeDisposition uint8

const (
	scopeFailed scopeDisposition = iota
	scopeSucceeded
	scopeConflicted
)

func (scope *executionScope) finish(disposition scopeDisposition) error {
	scope.mu.Lock()
	scope.terminal = true
	requireConsumed := disposition == scopeSucceeded
	var firstErr error
	for _, input := range scope.inputs {
		if requireConsumed && !input.opened && firstErr == nil {
			firstErr = ErrHandleNotConsumed
		}
		if input.reader != nil {
			if err := input.reader.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	for _, output := range scope.outputs {
		if output.output == nil {
			if requireConsumed && firstErr == nil {
				firstErr = ErrHandleNotConsumed
			}
			continue
		}
	}
	outputs := make([]*trackedOutput, 0, len(scope.outputs))
	for _, output := range scope.outputs {
		if output.output != nil {
			outputs = append(outputs, output.output)
		}
	}
	scope.mu.Unlock()
	if disposition == scopeSucceeded && firstErr == nil {
		for _, output := range outputs {
			if err := output.commit(); err != nil {
				firstErr = err
				break
			}
		}
	}
	if disposition != scopeSucceeded || firstErr != nil {
		for _, output := range outputs {
			if err := output.abort(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

type trackedOutput struct {
	mu       sync.Mutex
	output   Output
	terminal bool
}

func (output *trackedOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.terminal {
		return 0, ErrHandleConsumed
	}
	return output.output.Write(data)
}

func (output *trackedOutput) commit() error {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.terminal {
		return ErrHandleConsumed
	}
	if err := output.output.Commit(); err != nil {
		return err
	}
	output.terminal = true
	return nil
}

func (output *trackedOutput) abort() error {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.terminal {
		return nil
	}
	err := output.output.Abort()
	output.terminal = true
	return err
}

func (outcome Outcome) validate(kind ActionKind) error {
	count := 0
	for _, present := range []bool{outcome.Initialize != nil, outcome.Commit != nil, outcome.Materialize != nil, outcome.Conflict != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("%w: outcome must select exactly one variant", ErrInvalidOutcome)
	}
	switch {
	case outcome.Initialize != nil:
		if kind != ActionInitialize {
			return ErrInvalidOutcome
		}
		if err := outcome.Initialize.WorkspaceID.Validate(); err != nil {
			return ErrInvalidOutcome
		}
		if err := validateSHA256(outcome.Initialize.Commit); err != nil {
			return ErrInvalidOutcome
		}
		if err := outcome.Initialize.Root.Validate(); err != nil {
			return ErrInvalidOutcome
		}
	case outcome.Materialize != nil:
		if kind != ActionMaterialize {
			return ErrInvalidOutcome
		}
	case outcome.Conflict != nil:
		if kind == ActionInitialize || kind == ActionMaterialize {
			return ErrInvalidOutcome
		}
		if len(outcome.Conflict.Conflicts) == 0 || len(outcome.Conflict.Conflicts) > MaxResultConflicts {
			return ErrInvalidOutcome
		}
		for _, conflict := range outcome.Conflict.Conflicts {
			if err := conflict.ID.Validate(); err != nil {
				return ErrInvalidOutcome
			}
			if err := conflict.Target.Validate(); err != nil {
				return ErrInvalidOutcome
			}
			if err := conflict.Schema.Validate(); err != nil {
				return ErrInvalidOutcome
			}
			if conflict.Kind != ConflictConcurrentChange && conflict.Kind != ConflictUpdateDelete && conflict.Kind != ConflictAccess && conflict.Kind != ConflictPolicy {
				return ErrInvalidOutcome
			}
			for _, value := range []digest.Digest{conflict.Base, conflict.Ours, conflict.Theirs} {
				if value != "" {
					if err := validateSHA256(value); err != nil {
						return ErrInvalidOutcome
					}
				}
			}
		}
	case outcome.Commit != nil:
		if kind == ActionInitialize || kind == ActionMaterialize {
			return ErrInvalidOutcome
		}
		if err := validateSHA256(outcome.Commit.Commit); err != nil {
			return ErrInvalidOutcome
		}
		if err := outcome.Commit.Root.Validate(); err != nil {
			return ErrInvalidOutcome
		}
		if len(outcome.Commit.Changes) > MaxResultChanges {
			return ErrInvalidOutcome
		}
		for _, change := range outcome.Commit.Changes {
			if err := change.UID.Validate(); err != nil {
				return ErrInvalidOutcome
			}
			switch change.Kind {
			case ResourceCreated:
				if change.Before != "" || validateSHA256(change.After) != nil {
					return ErrInvalidOutcome
				}
			case ResourceUpdated:
				if validateSHA256(change.Before) != nil || validateSHA256(change.After) != nil {
					return ErrInvalidOutcome
				}
			case ResourceDeleted:
				if validateSHA256(change.Before) != nil || change.After != "" {
					return ErrInvalidOutcome
				}
			default:
				return ErrInvalidOutcome
			}
		}
	}
	return nil
}

func cloneOutcome(value Outcome) Outcome {
	if value.Initialize != nil {
		cloned := *value.Initialize
		value.Initialize = &cloned
	}
	if value.Materialize != nil {
		cloned := *value.Materialize
		value.Materialize = &cloned
	}
	if value.Commit != nil {
		cloned := *value.Commit
		cloned.Changes = append([]ResourceChange(nil), value.Commit.Changes...)
		value.Commit = &cloned
	}
	if value.Conflict != nil {
		cloned := *value.Conflict
		cloned.Conflicts = append([]ConflictSummary(nil), value.Conflict.Conflicts...)
		value.Conflict = &cloned
	}
	return value
}

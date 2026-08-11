// Package host is the typed, in-process application boundary shared by CLI,
// TUI, and desktop adapters. It owns workspace and operation capabilities;
// clients never receive storage, registry, key, or plaintext capabilities.
package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	DefaultHandleTTL            = 5 * time.Minute
	DefaultQueryCursorTTL       = 2 * time.Minute
	DefaultFinalizeTimeout      = 10 * time.Second
	MaxHandlesPerWorkspace      = 2_048
	MaxOperationsPerWorkspace   = 1_024
	MaxQueryCursorsPerWorkspace = 1_024
)

var (
	ErrInvalidWorkspace  = errors.New("host: invalid workspace")
	ErrWorkspaceClosed   = errors.New("host: workspace closed")
	ErrUnsupportedFormat = errors.New("host: unsupported legacy format")
	ErrInvalidAction     = errors.New("host: invalid action")
	ErrInvalidHandle     = errors.New("host: invalid or unavailable handle")
	ErrHandleExpired     = errors.New("host: handle expired")
	ErrHandleConsumed    = errors.New("host: handle already consumed")
	ErrHandleLimit       = errors.New("host: handle limit reached")
	ErrHandleNotConsumed = errors.New("host: executor did not consume handle")
	ErrUnknownOperation  = errors.New("host: unknown operation")
	ErrOperationLimit    = errors.New("host: operation limit reached")
	ErrInvalidProgress   = errors.New("host: invalid progress")
	ErrInvalidCursor     = errors.New("host: invalid progress cursor")
	ErrInvalidOutcome    = errors.New("host: invalid operation outcome")
)

type SessionID string
type OperationID string
type InputHandle string
type OutputHandle string

func (id OperationID) validate() error  { return validateCapability(string(id)) }
func (id InputHandle) validate() error  { return validateCapability(string(id)) }
func (id OutputHandle) validate() error { return validateCapability(string(id)) }

func validateCapability(value string) error {
	_, err := artifact.ParseUUID(value)
	return err
}

// InputSource and OutputTarget are registered once by a trusted native
// adapter. Actions carry only the resulting opaque handle.
type InputSource interface {
	Open(context.Context) (io.ReadCloser, error)
}

// Output is transactional. Commit or Abort must make the target terminal and
// release all native resources.
type Output interface {
	io.Writer
	Commit() error
	Abort() error
}

type OutputTarget interface {
	Open(context.Context) (Output, error)
}

// Execution is visible only to the process-wide Executor. It is never handed
// to a frontend adapter or encoded on a wire boundary.
type Execution interface {
	OperationID() artifact.UUID
	WorkspaceID() artifact.UUID
	Root() string
	ConfigRevision() digest.Digest
	OpenInput(InputHandle) (io.ReadCloser, error)
	OpenOutput(OutputHandle) (io.Writer, error)
	Report(ProgressPhase, ProgressUnit, uint64, uint64) error
}

// Executor is injected once at the trusted composition root. Unlike the old
// Action func, callers cannot inject executable behavior per operation.
//
// Finalize is called exactly once after every claimed stream is terminal: a
// successful non-conflict outcome has committed its outputs, while failures
// and conflicts have aborted them. Its context ignores operation cancellation
// but has DefaultFinalizeTimeout as a deadline. A Finalize error fails the
// operation. Already-committed outputs cannot be rolled back and remain
// committed when terminal audit persistence fails.
type Executor interface {
	Execute(context.Context, Execution, Action) (Outcome, error)
	Finalize(context.Context, Execution, Action, Outcome, error) error
}

type OpenWorkspaceRequest struct {
	WorkspaceID    artifact.UUID
	Root           string
	ConfigRevision digest.Digest
}

type Host struct {
	executor       Executor
	queries        QueryExecutor
	now            func() time.Time
	handleTTL      time.Duration
	queryCursorTTL time.Duration

	mu         sync.RWMutex
	workspaces map[SessionID]*workspaceState
}

// New builds a host around trusted mutation and read-only executors. Both are
// injected once at the native composition root, never by an individual client.
func New(executor Executor, queries QueryExecutor) (*Host, error) {
	return newHost(executor, queries, time.Now, DefaultHandleTTL, DefaultQueryCursorTTL)
}

func newHost(executor Executor, queries QueryExecutor, now func() time.Time, handleTTL, queryCursorTTL time.Duration) (*Host, error) {
	if isNilInterface(executor) || isNilInterface(queries) || now == nil || handleTTL <= 0 || queryCursorTTL <= 0 {
		return nil, fmt.Errorf("%w: invalid host dependencies", ErrInvalidWorkspace)
	}
	return &Host{
		executor: executor, queries: queries, now: now, handleTTL: handleTTL, queryCursorTTL: queryCursorTTL,
		workspaces: make(map[SessionID]*workspaceState),
	}, nil
}

type workspaceState struct {
	id             SessionID
	workspaceID    artifact.UUID
	root           string
	configRevision digest.Digest
	hostContext    context.Context
	cancel         context.CancelFunc

	mu           sync.Mutex
	closed       bool
	inputs       map[InputHandle]inputLease
	outputs      map[OutputHandle]outputLease
	queryCursors map[QueryCursor]queryCursorLease
	operations   map[OperationID]*operationState
	completed    []OperationID
}

type inputLease struct {
	source    InputSource
	expiresAt time.Time
}

type outputLease struct {
	target    OutputTarget
	expiresAt time.Time
}

// Workspace is an opaque, non-serializable session capability. Its immutable
// root and storage dependencies have no client-facing accessors.
type Workspace struct {
	host  *Host
	state *workspaceState
}

// Close cancels and drains every workspace opened by this process. It is used
// by the native composition root before storage, audit, or credential-backed
// dependencies are released.
func (host *Host) Close(ctx context.Context) error {
	if host == nil {
		return nil
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidWorkspace)
	}
	host.mu.RLock()
	workspaces := make([]*Workspace, 0, len(host.workspaces))
	for _, state := range host.workspaces {
		workspaces = append(workspaces, &Workspace{host: host, state: state})
	}
	host.mu.RUnlock()
	var result error
	for _, workspace := range workspaces {
		if err := workspace.Close(ctx); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (workspace *Workspace) ID() SessionID {
	if workspace == nil || workspace.state == nil {
		return ""
	}
	return workspace.state.id
}

func (host *Host) OpenWorkspace(ctx context.Context, request OpenWorkspaceRequest) (*Workspace, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidWorkspace)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := request.WorkspaceID.Validate(); err != nil {
		return nil, fmt.Errorf("%w: workspace ID: %v", ErrInvalidWorkspace, err)
	}
	if err := validateSHA256(request.ConfigRevision); err != nil {
		return nil, fmt.Errorf("%w: configuration revision: %v", ErrInvalidWorkspace, err)
	}
	if err := validateWorkspaceRoot(request.Root); err != nil {
		return nil, err
	}
	if err := rejectLegacyConfiguration(request.Root); err != nil {
		return nil, err
	}
	idValue, err := newUUID()
	if err != nil {
		return nil, err
	}
	id := SessionID(idValue)
	hostContext, cancel := context.WithCancel(context.Background())
	state := &workspaceState{
		id: id, workspaceID: request.WorkspaceID, root: request.Root,
		configRevision: request.ConfigRevision, hostContext: hostContext, cancel: cancel,
		inputs: make(map[InputHandle]inputLease), outputs: make(map[OutputHandle]outputLease),
		queryCursors: make(map[QueryCursor]queryCursorLease),
		operations:   make(map[OperationID]*operationState),
	}
	host.mu.Lock()
	host.workspaces[id] = state
	host.mu.Unlock()
	return &Workspace{host: host, state: state}, nil
}

func validateWorkspaceRoot(root string) error {
	if err := validateCapabilityPath(root); err != nil {
		return fmt.Errorf("%w: root must be absolute and clean", ErrInvalidWorkspace)
	}
	if err := validatePinnedDirectory(root); err != nil {
		return fmt.Errorf("%w: root must be a pinned native directory", ErrInvalidWorkspace)
	}
	return nil
}

func rejectLegacyConfiguration(root string) error {
	for _, name := range []string{"enbu.toml", ".enbu.local"} {
		_, err := os.Lstat(filepath.Join(root, name))
		switch {
		case err == nil:
			return fmt.Errorf("%w: %s", ErrUnsupportedFormat, name)
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return fmt.Errorf("%w: inspect %s: %v", ErrInvalidWorkspace, name, err)
		}
	}
	return nil
}

func (workspace *Workspace) RegisterInput(ctx context.Context, source InputSource) (InputHandle, error) {
	if ctx == nil || isNilInterface(source) {
		return "", fmt.Errorf("%w: input source", ErrInvalidHandle)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	state, err := workspace.validState()
	if err != nil {
		return "", err
	}
	value, err := newUUID()
	if err != nil {
		return "", err
	}
	handle := InputHandle(value)
	now := workspace.host.now()
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return "", ErrWorkspaceClosed
	}
	state.purgeExpiredHandles(now)
	if len(state.inputs)+len(state.outputs) >= MaxHandlesPerWorkspace {
		return "", ErrHandleLimit
	}
	state.inputs[handle] = inputLease{source: source, expiresAt: now.Add(workspace.host.handleTTL)}
	return handle, nil
}

func (workspace *Workspace) RegisterOutput(ctx context.Context, target OutputTarget) (OutputHandle, error) {
	if ctx == nil || isNilInterface(target) {
		return "", fmt.Errorf("%w: output target", ErrInvalidHandle)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	state, err := workspace.validState()
	if err != nil {
		return "", err
	}
	value, err := newUUID()
	if err != nil {
		return "", err
	}
	handle := OutputHandle(value)
	now := workspace.host.now()
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return "", ErrWorkspaceClosed
	}
	state.purgeExpiredHandles(now)
	if len(state.inputs)+len(state.outputs) >= MaxHandlesPerWorkspace {
		return "", ErrHandleLimit
	}
	state.outputs[handle] = outputLease{target: target, expiresAt: now.Add(workspace.host.handleTTL)}
	return handle, nil
}

func (state *workspaceState) purgeExpiredHandles(now time.Time) {
	for handle, lease := range state.inputs {
		if !now.Before(lease.expiresAt) {
			delete(state.inputs, handle)
		}
	}
	for handle, lease := range state.outputs {
		if !now.Before(lease.expiresAt) {
			delete(state.outputs, handle)
		}
	}
}

func (workspace *Workspace) Start(ctx context.Context, requested Action) (OperationID, error) {
	if ctx == nil {
		return "", fmt.Errorf("%w: nil context", ErrInvalidAction)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	state, err := workspace.validState()
	if err != nil {
		return "", err
	}
	action, err := cloneAction(requested)
	if err != nil {
		return "", err
	}
	if err := action.validate(); err != nil {
		return "", err
	}
	value, err := newUUID()
	if err != nil {
		return "", err
	}
	id := OperationID(value)
	runContext, cancel := context.WithCancel(state.hostContext)
	stopCaller := context.AfterFunc(ctx, cancel)

	state.mu.Lock()
	if state.closed {
		state.mu.Unlock()
		stopCaller()
		cancel()
		return "", ErrWorkspaceClosed
	}
	state.pruneCompletedForStart()
	if len(state.operations) >= MaxOperationsPerWorkspace {
		state.mu.Unlock()
		stopCaller()
		cancel()
		return "", ErrOperationLimit
	}
	inputs, outputs, err := state.claimHandles(action.handles(), workspace.host.now())
	if err != nil {
		state.mu.Unlock()
		stopCaller()
		cancel()
		return "", err
	}
	operation := newOperationState(id, action.Kind(), cancel)
	state.operations[id] = operation
	state.mu.Unlock()

	scope := newExecutionScope(runContext, state, operation, inputs, outputs)
	go workspace.host.runOperation(runContext, stopCaller, operation, scope, action)
	return id, nil
}

// pruneCompletedForStart prevents a long-lived multi-client process from
// exhausting its operation allowance merely because clients have already
// observed terminal operations. Running operations are never evicted.
func (state *workspaceState) pruneCompletedForStart() {
	for len(state.operations) >= MaxOperationsPerWorkspace && len(state.completed) > 0 {
		id := state.completed[0]
		state.completed = state.completed[1:]
		operation := state.operations[id]
		if operation != nil && operation.terminal() {
			delete(state.operations, id)
		}
	}
	if len(state.operations) < MaxOperationsPerWorkspace {
		return
	}
	// Completion recording happens immediately after the terminal state is
	// published. A concurrent Start can briefly arrive in between, so scan once
	// rather than reporting a false lifetime limit.
	for id, operation := range state.operations {
		if operation.terminal() {
			delete(state.operations, id)
			return
		}
	}
}

func (state *workspaceState) recordCompleted(id OperationID, operation *operationState) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.operations[id] == operation {
		state.completed = append(state.completed, id)
	}
}

func (state *workspaceState) claimHandles(refs actionHandles, now time.Time) (map[InputHandle]InputSource, map[OutputHandle]OutputTarget, error) {
	seenInputs := make(map[InputHandle]struct{}, len(refs.inputs))
	seenOutputs := make(map[OutputHandle]struct{}, len(refs.outputs))
	for _, handle := range refs.inputs {
		if err := handle.validate(); err != nil {
			return nil, nil, fmt.Errorf("%w: input", ErrInvalidHandle)
		}
		if _, duplicate := seenInputs[handle]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate input", ErrInvalidHandle)
		}
		lease, exists := state.inputs[handle]
		if !exists {
			return nil, nil, ErrInvalidHandle
		}
		if !now.Before(lease.expiresAt) {
			delete(state.inputs, handle)
			return nil, nil, ErrHandleExpired
		}
		seenInputs[handle] = struct{}{}
	}
	for _, handle := range refs.outputs {
		if err := handle.validate(); err != nil {
			return nil, nil, fmt.Errorf("%w: output", ErrInvalidHandle)
		}
		if _, duplicate := seenOutputs[handle]; duplicate {
			return nil, nil, fmt.Errorf("%w: duplicate output", ErrInvalidHandle)
		}
		lease, exists := state.outputs[handle]
		if !exists {
			return nil, nil, ErrInvalidHandle
		}
		if !now.Before(lease.expiresAt) {
			delete(state.outputs, handle)
			return nil, nil, ErrHandleExpired
		}
		seenOutputs[handle] = struct{}{}
	}
	state.purgeExpiredHandles(now)
	inputs := make(map[InputHandle]InputSource, len(seenInputs))
	for handle := range seenInputs {
		inputs[handle] = state.inputs[handle].source
		delete(state.inputs, handle)
	}
	outputs := make(map[OutputHandle]OutputTarget, len(seenOutputs))
	for handle := range seenOutputs {
		outputs[handle] = state.outputs[handle].target
		delete(state.outputs, handle)
	}
	return inputs, outputs, nil
}

func (workspace *Workspace) validState() (*workspaceState, error) {
	if workspace == nil || workspace.host == nil || workspace.state == nil {
		return nil, ErrInvalidWorkspace
	}
	workspace.host.mu.RLock()
	registered := workspace.host.workspaces[workspace.state.id] == workspace.state
	workspace.host.mu.RUnlock()
	if !registered {
		workspace.state.mu.Lock()
		closed := workspace.state.closed
		workspace.state.mu.Unlock()
		if closed {
			return workspace.state, nil
		}
		return nil, ErrInvalidWorkspace
	}
	return workspace.state, nil
}

func (workspace *Workspace) Close(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidWorkspace)
	}
	state, err := workspace.validState()
	if err != nil {
		return err
	}
	state.mu.Lock()
	if !state.closed {
		state.closed = true
		state.inputs = make(map[InputHandle]inputLease)
		state.outputs = make(map[OutputHandle]outputLease)
		state.queryCursors = make(map[QueryCursor]queryCursorLease)
		state.cancel()
	}
	operations := make([]*operationState, 0, len(state.operations))
	for _, operation := range state.operations {
		operation.requestCancel()
		operations = append(operations, operation)
	}
	state.mu.Unlock()
	for _, operation := range operations {
		select {
		case <-operation.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	workspace.host.mu.Lock()
	if workspace.host.workspaces[state.id] == state {
		delete(workspace.host.workspaces, state.id)
	}
	workspace.host.mu.Unlock()
	return nil
}

func newUUID() (artifact.UUID, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	value := hex.EncodeToString(raw[:])
	return artifact.ParseUUID(value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:])
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

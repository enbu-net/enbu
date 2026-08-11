package apphost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/cas"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/enrollment"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/plugin"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/enbu-net/enbu/pkg/workspace"
	"github.com/opencontainers/go-digest"
)

type workspaceState struct {
	root     string
	stateDir string
	config   workspace.Config
	revision digest.Digest
	objects  *cas.Store
	remote   registry.Remote
	device   *artifact.DeviceIdentity
	author   artifact.VerifiedDevice
	verifier *enrollment.Verifier
	audit    engine.AuditTrail

	auditCloser io.Closer

	enrollmentMu     sync.RWMutex
	knownEnrollments map[digest.Digest]artifact.VerifiedDevice

	closeMu       sync.Mutex
	auditClosed   bool
	objectsClosed bool
}

type Executor struct {
	mu            sync.RWMutex
	states        map[artifact.UUID]*workspaceState
	finalizations map[artifact.UUID]pendingFinalization
	gates         map[artifact.UUID]chan struct{}
	plugins       PluginResolver
	pluginHost    *plugin.Host
}

func newExecutor() *Executor {
	return &Executor{
		states:        make(map[artifact.UUID]*workspaceState),
		finalizations: make(map[artifact.UUID]pendingFinalization),
		gates:         make(map[artifact.UUID]chan struct{}),
	}
}

func (executor *Executor) register(state *workspaceState) (*workspaceState, error) {
	if state == nil {
		return nil, errors.New("apphost: nil workspace state")
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	existing := executor.states[state.config.Workspace]
	if existing == nil {
		executor.states[state.config.Workspace] = state
		return state, nil
	}
	if existing.root != state.root || existing.revision != state.revision || existing.config.Registry != state.config.Registry {
		return nil, ErrStateConflict
	}
	return existing, nil
}

func (executor *Executor) lookup(execution host.Execution) (*workspaceState, error) {
	if execution == nil {
		return nil, errors.New("apphost: nil execution")
	}
	executor.mu.RLock()
	state := executor.states[execution.WorkspaceID()]
	executor.mu.RUnlock()
	if state == nil || state.root != execution.Root() || state.revision != execution.ConfigRevision() {
		return nil, ErrStateConflict
	}
	return state, nil
}

func (executor *Executor) close(ctx context.Context) error {
	executor.mu.RLock()
	states := make(map[artifact.UUID]*workspaceState, len(executor.states))
	for id, state := range executor.states {
		states[id] = state
	}
	executor.mu.RUnlock()
	var result error
	for id, state := range states {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		if err := state.close(ctx); err != nil {
			result = errors.Join(result, err)
			continue
		}
		executor.mu.Lock()
		if executor.states[id] == state {
			delete(executor.states, id)
			delete(executor.gates, id)
		}
		executor.mu.Unlock()
	}
	return result
}

func (state *workspaceState) close(ctx context.Context) error {
	state.closeMu.Lock()
	defer state.closeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !state.auditClosed {
		if state.auditCloser != nil {
			if err := state.auditCloser.Close(); err != nil {
				return err
			}
		}
		state.auditClosed = true
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !state.objectsClosed {
		if err := state.objects.Close(); err != nil {
			return err
		}
		state.objectsClosed = true
	}
	return nil
}

func (executor *Executor) Execute(ctx context.Context, execution host.Execution, action host.Action) (host.Outcome, error) {
	state, err := executor.lookup(execution)
	if err != nil {
		return host.Outcome{}, err
	}
	if action.Kind() != host.ActionMaterialize {
		release, err := executor.acquireMutation(ctx, state.config.Workspace)
		if err != nil {
			return host.Outcome{}, err
		}
		defer release()
	}
	switch typed := action.(type) {
	case host.InitializeAction:
		return executor.initialize(ctx, execution, state, typed)
	case host.ApplyAction:
		return executor.apply(ctx, execution, state, typed)
	case host.TransformAction:
		return executor.transform(ctx, execution, state, typed)
	case host.MaterializeAction:
		return executor.materialize(ctx, execution, state, typed)
	case host.ChangeAccessAction:
		return executor.changeAccess(ctx, execution, state, typed)
	case host.ChangePolicyAction:
		return executor.changePolicy(ctx, execution, state, typed)
	case host.MergeAction:
		return executor.merge(ctx, execution, state, typed)
	case host.RestoreAction:
		return executor.restore(ctx, execution, state, typed)
	default:
		return host.Outcome{}, host.ErrInvalidAction
	}
}

// acquireMutation serializes mutations from every in-process session for one
// workspace. The map mutex is held only while resolving the gate; it is never
// held across CAS, cryptography, policy, audit, or registry I/O.
func (executor *Executor) acquireMutation(ctx context.Context, workspaceID artifact.UUID) (func(), error) {
	executor.mu.Lock()
	gate := executor.gates[workspaceID]
	if gate == nil {
		gate = make(chan struct{}, 1)
		gate <- struct{}{}
		executor.gates[workspaceID] = gate
	}
	executor.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-gate:
		return func() { gate <- struct{}{} }, nil
	}
}

func (executor *Executor) initialize(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	action host.InitializeAction,
) (host.Outcome, error) {
	if action.OwnerEnrollment != state.author.AssertionDigest() {
		return host.Outcome{}, errors.New("apphost: owner enrollment mismatch")
	}
	if err := execution.Report(host.PhaseDiscovering, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	discovery, err := executor.discover(ctx, state)
	if err != nil {
		return host.Outcome{}, err
	}
	if len(discovery.Announcements) != 0 || len(discovery.Inaccessible) != 0 {
		return host.Outcome{}, ErrAlreadyInitialized
	}
	if err := executor.beginFinalization(ctx, state.audit, execution.OperationID(), engine.AuditActionInitialize, state.revision); err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhaseSealing, host.ProgressUnitItems, 0, 2); err != nil {
		return host.Outcome{}, err
	}
	policyDraft, err := draftFromAction(execution, action.Policy)
	if err != nil {
		return host.Outcome{}, err
	}
	sealer := engine.Sealer{Sink: state.objects, Issuer: state.device, Recipients: []artifact.VerifiedDevice{state.author}}
	sealedPolicy, err := sealer.SealPolicyDraft(ctx, policyDraft)
	if err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhaseSealing, host.ProgressUnitItems, 1, 2); err != nil {
		return host.Outcome{}, err
	}
	rootDraft, err := draftFromAction(execution, action.Root)
	if err != nil {
		return host.Outcome{}, err
	}
	sealedRoot, err := sealer.SealDraft(ctx, rootDraft, sealedPolicy.Ref.Revision)
	if err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhaseSealing, host.ProgressUnitItems, 2, 2); err != nil {
		return host.Outcome{}, err
	}
	provenanceID, err := newUUID()
	if err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhasePublishing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	published, err := (engine.Publisher{
		Local: state.objects, Remote: state.remote, Device: state.device, Author: state.author,
		Recipients: []artifact.VerifiedDevice{state.author}, Audit: state.audit, AuditExternallyManaged: true,
	}).Publish(ctx, engine.AuditActionInitialize, engine.CommitMutation{
		WorkspaceID: state.config.Workspace,
		Root:        sealedRoot.Ref, Policy: sealedPolicy.Ref,
		Actor: state.author.Subject(), OperationID: execution.OperationID(),
		Provenance: []commitmodel.MutationProvenance{{
			ID: provenanceID, Action: commitmodel.InitializeAction(), Target: sealedRoot.Revision.UID, After: &sealedRoot.Ref,
		}},
		Closure: engine.MergeClosures(sealedRoot.Closure, sealedPolicy.Closure),
	})
	if err != nil {
		return host.Outcome{}, err
	}
	return host.Outcome{Initialize: &host.InitializeResult{
		WorkspaceID: state.config.Workspace, Commit: published.CommitID, Root: sealedRoot.Ref,
	}}, nil
}

func draftFromAction(execution host.Execution, draft host.DraftResource) (engine.Draft, error) {
	converted := engine.Draft{
		Kind: draft.Kind, UID: draft.UID, Schema: draft.Schema, Metadata: draft.Metadata,
		Edges: append([]artifact.Edge(nil), draft.Edges...),
	}
	for _, payload := range draft.Payloads {
		reader, err := execution.OpenInput(payload.Source)
		if err != nil {
			return engine.Draft{}, err
		}
		converted.Payloads = append(converted.Payloads, engine.PayloadSource{
			Name: payload.Name, MediaType: payload.MediaType, Reader: reader,
		})
	}
	return converted, nil
}

func (executor *Executor) discover(ctx context.Context, state *workspaceState) (registry.Discovery, error) {
	verifier, err := registry.NewEncryptedCommitVerifier(state.remote, state.device, state.verifier)
	if err != nil {
		return registry.Discovery{}, err
	}
	return registry.Discover(ctx, state.config.Workspace, state.remote, verifier)
}

// completeDAG is the sole correctness path for history discovery. A logical
// Commit that is only present through inaccessible envelope variants makes the
// frontier unknowable and therefore aborts every query and mutation. An
// inaccessible duplicate is harmless only when the same logical Commit was
// authenticated through another accessible announcement.
func (executor *Executor) completeDAG(ctx context.Context, state *workspaceState) (*commitmodel.DAG, error) {
	discovery, err := executor.discover(ctx, state)
	if err != nil {
		return nil, err
	}
	return completeDAGFromDiscovery(ctx, discovery)
}

func completeDAGFromDiscovery(ctx context.Context, discovery registry.Discovery) (*commitmodel.DAG, error) {
	accessible := make(map[digest.Digest]struct{}, len(discovery.Announcements))
	for _, announcement := range discovery.Announcements {
		accessible[announcement.Commit.CommitID] = struct{}{}
	}
	for _, announcement := range discovery.Inaccessible {
		if _, exists := accessible[announcement.CommitID]; !exists {
			return nil, fmt.Errorf("%w: inaccessible logical commit %s", artifact.ErrGrantAccessDenied, announcement.CommitID)
		}
	}
	if len(discovery.Announcements) == 0 {
		return nil, nil
	}
	return discovery.BuildDAG(ctx)
}

type fallbackSource struct {
	local  *cas.Store
	remote registry.Remote
}

func (source fallbackSource) Open(ctx context.Context, value digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	reader, descriptor, err := source.local.Open(ctx, value)
	if err == nil || !errors.Is(err, cas.ErrNotFound) {
		return reader, descriptor, err
	}
	return source.remote.Open(ctx, value)
}

var _ host.Executor = (*Executor)(nil)

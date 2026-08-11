package apphost

import (
	"context"
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/schema"
	"github.com/opencontainers/go-digest"
)

func (executor *Executor) changePolicy(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	action host.ChangePolicyAction,
) (host.Outcome, error) {
	if err := execution.Report(host.PhaseDiscovering, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	dag, err := executor.completeDAG(ctx, state)
	if err != nil {
		return host.Outcome{}, err
	}
	if dag == nil {
		return host.Outcome{}, commitmodel.ErrCommitNotFound
	}
	base, exists := dag.Commit(action.BaseCommit)
	if !exists {
		return host.Outcome{}, commitmodel.ErrCommitNotFound
	}
	if frontier := dag.Frontier(); len(frontier) != 1 || frontier[0] != action.BaseCommit {
		return conflictForPolicyFrontier(base, action.BaseCommit, frontier)
	}
	if base.Policy != action.Expected {
		return host.Outcome{}, errors.New("apphost: expected policy revision does not match base Commit")
	}
	if err := executor.beginFinalization(ctx, state.audit, execution.OperationID(), engine.AuditActionChangePolicy, base.Policy.Material); err != nil {
		return host.Outcome{}, err
	}
	source := fallbackSource{local: state.objects, remote: state.remote}
	openedPolicy, err := engine.OpenRevision(ctx, source, state.device, state.verifier, base.Policy)
	if err != nil {
		return host.Outcome{}, err
	}
	if openedPolicy.Grant.Claims.Issuer != state.device.DeviceID() {
		return host.Outcome{}, errors.New("apphost: only the current policy issuer may replace policy")
	}
	rego, _ := artifact.ParseTypeRef(schema.SchemaRegoPolicy)
	if action.Policy.UID != openedPolicy.Revision.UID || action.Policy.Schema != rego {
		return host.Outcome{}, errors.New("apphost: replacement policy must preserve UID and RegoPolicy schema")
	}
	graph, err := engine.OpenGraph(ctx, source, state.device, state.verifier, base.Root)
	if err != nil {
		return host.Outcome{}, err
	}
	rootOpened := graph.ByRevision[graph.Root.Revision]
	recipients, err := verifiedGrantRecipients(ctx, rootOpened.Grant.Claims.Recipients, state.verifier)
	if err != nil {
		return host.Outcome{}, err
	}
	draft, err := draftFromAction(execution, action.Policy)
	if err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhaseSealing, host.ProgressUnitItems, 0, 1); err != nil {
		return host.Outcome{}, err
	}
	sealed, err := (engine.Sealer{Sink: state.objects, Issuer: state.device, Recipients: recipients}).SealPolicyDraft(ctx, draft)
	if err != nil {
		return host.Outcome{}, err
	}
	if sealed.Ref == base.Policy {
		return host.Outcome{}, errors.New("apphost: policy replacement produced no change")
	}
	if outcome, conflict, err := executor.recheckBaseFrontier(ctx, state, base, action.BaseCommit); err != nil {
		return host.Outcome{}, err
	} else if conflict {
		return outcome, nil
	}
	provenanceID, err := newUUID()
	if err != nil {
		return host.Outcome{}, err
	}
	actionType, _ := artifact.ParseTypeRef("operations.enbu.net/v1alpha1/ChangePolicy")
	before, after := base.Policy, sealed.Ref
	closure := sealed.Closure
	for _, opened := range graph.ByUID {
		closure = engine.MergeClosures(closure, closureForOpened(opened))
	}
	published, err := (engine.Publisher{
		Local: state.objects, Remote: state.remote, Device: state.device, Author: state.author,
		Recipients: recipients, Audit: state.audit, AuditExternallyManaged: true,
	}).Publish(ctx, engine.AuditActionChangePolicy, engine.CommitMutation{
		WorkspaceID: state.config.Workspace, Root: base.Root, Policy: sealed.Ref,
		Parents: []digest.Digest{action.BaseCommit}, Actor: state.author.Subject(), OperationID: execution.OperationID(),
		Provenance: []commitmodel.MutationProvenance{{
			ID: provenanceID, Action: actionType, Target: action.Policy.UID, Before: &before, After: &after,
		}},
		Closure: closure,
	})
	if err != nil {
		return host.Outcome{}, fmt.Errorf("publish policy replacement: %w", err)
	}
	return host.Outcome{Commit: &host.CommitResult{
		Commit: published.CommitID, Root: base.Root,
		Changes: []host.ResourceChange{{UID: action.Policy.UID, Kind: host.ResourceUpdated, Before: before.Revision, After: after.Revision}},
	}}, nil
}

func conflictForPolicyFrontier(base commitmodel.Commit, baseID digest.Digest, frontier []digest.Digest) (host.Outcome, error) {
	rego, _ := artifact.ParseTypeRef(schema.SchemaRegoPolicy)
	conflicts := make([]host.ConflictSummary, 0, max(1, len(frontier)))
	for _, head := range frontier {
		if head == baseID {
			continue
		}
		id, err := newUUID()
		if err != nil {
			return host.Outcome{}, err
		}
		conflicts = append(conflicts, host.ConflictSummary{
			ID: id, Target: base.WorkspaceID, Schema: rego, Kind: host.ConflictPolicy,
			Base: baseID, Ours: baseID, Theirs: head,
		})
	}
	if len(conflicts) == 0 {
		id, err := newUUID()
		if err != nil {
			return host.Outcome{}, err
		}
		conflicts = append(conflicts, host.ConflictSummary{ID: id, Target: base.WorkspaceID, Schema: rego, Kind: host.ConflictPolicy, Base: baseID})
	}
	return host.Outcome{Conflict: &host.ConflictResult{Conflicts: conflicts}}, nil
}

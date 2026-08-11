package apphost

import (
	"context"
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/opencontainers/go-digest"
)

func (executor *Executor) restore(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	action host.RestoreAction,
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
	baseCommit, ok := dag.Commit(action.BaseCommit)
	if !ok {
		return host.Outcome{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, action.BaseCommit)
	}
	if frontier := dag.Frontier(); len(frontier) != 1 || frontier[0] != action.BaseCommit {
		return conflictForFrontier(baseCommit, action.BaseCommit, frontier)
	}
	sourceCommit, ok := dag.Commit(action.SourceCommit)
	if !ok {
		return host.Outcome{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, action.SourceCommit)
	}
	reachable, err := dag.Reachable(action.BaseCommit, action.SourceCommit)
	if err != nil {
		return host.Outcome{}, err
	}
	if !reachable {
		return host.Outcome{}, errors.New("apphost: restore source is not an ancestor of the selected base")
	}
	if err := executor.beginFinalization(ctx, state.audit, execution.OperationID(), engine.AuditActionRestore, baseCommit.Root.Material); err != nil {
		return host.Outcome{}, err
	}

	if err := execution.Report(host.PhaseDecrypting, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	objectSource := fallbackSource{local: state.objects, remote: state.remote}
	baseGraph, err := engine.OpenGraph(ctx, objectSource, state.device, state.verifier, baseCommit.Root)
	if err != nil {
		return host.Outcome{}, err
	}
	sourceGraph, err := engine.OpenGraph(ctx, objectSource, state.device, state.verifier, sourceCommit.Root)
	if err != nil {
		return host.Outcome{}, err
	}
	openedPolicy, err := engine.OpenRevision(ctx, objectSource, state.device, state.verifier, baseCommit.Policy)
	if err != nil {
		return host.Outcome{}, fmt.Errorf("open current pinned policy: %w", err)
	}
	baseRoot := baseGraph.ByRevision[baseGraph.Root.Revision]
	sourceRoot := sourceGraph.ByRevision[sourceGraph.Root.Revision]
	if baseRoot.Revision.UID == "" || sourceRoot.Revision.UID == "" || baseRoot.Revision.UID != sourceRoot.Revision.UID {
		return host.Outcome{}, errors.New("apphost: restore source has a different workspace root")
	}

	nodes := make(map[artifact.UUID]*revisionPlan, len(sourceGraph.ByUID))
	for uid, opened := range sourceGraph.ByUID {
		var recipients []artifact.VerifiedDevice
		if current, exists := baseGraph.ByUID[uid]; exists {
			recipients, err = verifiedGrantRecipients(ctx, current.Grant.Claims.Recipients, state.verifier)
		} else {
			// The current graph has no authoritative recipient set for a deleted
			// object. Restoring its old Grant could resurrect revoked access, so
			// fail-safe access is the publishing device only.
			recipients = []artifact.VerifiedDevice{state.author}
		}
		if err != nil {
			return host.Outcome{}, err
		}
		plan := revisionPlanFromOpened(opened, recipients)
		// Never reuse historical Material identities during restore. Content is
		// copied into a new child Commit; old access capabilities stay historical.
		plan.forceSeal = true
		nodes[uid] = plan
	}

	if err := execution.Report(host.PhaseSealing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	builder := newGraphResealer(ctx, state, baseCommit.Policy, nodes)
	newRoot, err := builder.seal(sourceRoot.Revision.UID)
	if err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhasePublishing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	if outcome, conflict, err := executor.recheckBaseFrontier(ctx, state, baseCommit, action.BaseCommit); err != nil {
		return host.Outcome{}, err
	} else if conflict {
		return outcome, nil
	}

	provenanceID, err := newUUID()
	if err != nil {
		return host.Outcome{}, err
	}
	actionType, _ := artifact.ParseTypeRef("operations.enbu.net/v1alpha1/Restore")
	sourceRole, _ := artifact.ParseTypeRef("inputs.enbu.net/v1alpha1/Source")
	before, after := baseCommit.Root, newRoot
	provenance := []commitmodel.MutationProvenance{{
		ID: provenanceID, Action: actionType, Target: sourceRoot.Revision.UID,
		Before: &before, After: &after,
		Inputs: []commitmodel.PinnedInput{{Role: sourceRole, UID: sourceRoot.Revision.UID, Sealed: sourceCommit.Root}},
	}}
	closure := engine.MergeClosures(builder.closure(), closureForOpened(openedPolicy))
	published, err := (engine.Publisher{
		Local: state.objects, Remote: state.remote, Device: state.device, Author: state.author,
		Recipients: append([]artifact.VerifiedDevice(nil), nodes[sourceRoot.Revision.UID].recipients...), Audit: state.audit, AuditExternallyManaged: true,
	}).Publish(ctx, engine.AuditActionRestore, engine.CommitMutation{
		WorkspaceID: state.config.Workspace, Root: newRoot, Policy: baseCommit.Policy,
		Parents: []digest.Digest{action.BaseCommit}, Actor: state.author.Subject(), OperationID: execution.OperationID(),
		Provenance: provenance, Closure: closure,
	})
	if err != nil {
		return host.Outcome{}, err
	}
	return host.Outcome{Commit: &host.CommitResult{
		Commit: published.CommitID, Root: newRoot,
		Changes: []host.ResourceChange{{UID: sourceRoot.Revision.UID, Kind: host.ResourceUpdated, Before: before.Revision, After: after.Revision}},
	}}, nil
}

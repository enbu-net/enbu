package apphost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/policy"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/enbu-net/enbu/pkg/schema"
	"github.com/opencontainers/go-digest"
)

func (executor *Executor) changeAccess(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	action host.ChangeAccessAction,
) (host.Outcome, error) {
	if err := execution.Report(host.PhaseDiscovering, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	discovery, err := executor.discover(ctx, state)
	if err != nil {
		return host.Outcome{}, err
	}
	dag, err := completeDAGFromDiscovery(ctx, discovery)
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
	if err := executor.beginFinalization(ctx, state.audit, execution.OperationID(), engine.AuditActionChangeAccess, baseCommit.Root.Material); err != nil {
		return host.Outcome{}, err
	}

	if err := execution.Report(host.PhaseDecrypting, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	source := fallbackSource{local: state.objects, remote: state.remote}
	graph, err := engine.OpenGraph(ctx, source, state.device, state.verifier, baseCommit.Root)
	if err != nil {
		return host.Outcome{}, err
	}
	openedPolicy, err := engine.OpenRevision(ctx, source, state.device, state.verifier, baseCommit.Policy)
	if err != nil {
		return host.Outcome{}, fmt.Errorf("open pinned policy: %w", err)
	}
	known, err := collectKnownRecipients(ctx, graph, openedPolicy, state)
	if err != nil {
		return host.Outcome{}, err
	}
	candidates := make([]artifact.VerifiedDevice, 0, len(action.Candidates))
	for _, candidate := range action.Candidates {
		verified, exists := known[candidate.Digest]
		if !exists {
			// A digest is an identity, not an assertion transport. Unknown
			// enrollments fail closed until a trusted enrollment object/handle
			// has made the assertion known to this workspace.
			return host.Outcome{}, fmt.Errorf("apphost: unknown candidate enrollment %s", candidate.Digest)
		}
		candidates = append(candidates, verified)
	}
	sortRecipients(candidates)

	var policySource []byte
	if action.Mode == host.AccessGrant {
		policySource, err = readPolicySource(ctx, source, openedPolicy)
		if err != nil {
			return host.Outcome{}, err
		}
		defer wipeSensitive(policySource)
	}

	nodes := make(map[artifact.UUID]*revisionPlan, len(graph.ByUID))
	for uid, opened := range graph.ByUID {
		recipients, recipientErr := verifiedGrantRecipients(ctx, opened.Grant.Claims.Recipients, state.verifier)
		if recipientErr != nil {
			return host.Outcome{}, recipientErr
		}
		nodes[uid] = revisionPlanFromOpened(opened, recipients)
	}
	targets := append([]artifact.UUID(nil), action.Targets...)
	if action.Mode == host.AccessGrant {
		targets, err = expandGrantTargets(graph, targets)
		if err != nil {
			return host.Outcome{}, err
		}
		if err := execution.Report(host.PhasePolicy, host.ProgressUnitItems, 0, uint64(len(targets)*len(candidates))); err != nil {
			return host.Outcome{}, err
		}
	}
	sort.Slice(targets, func(i, j int) bool { return string(targets[i]) < string(targets[j]) })
	policyEngine := policy.New()
	policyEvaluations := uint64(0)
	for _, target := range targets {
		plan := nodes[target]
		if plan == nil || plan.source == nil {
			return host.Outcome{}, fmt.Errorf("apphost: access target %s is not in the selected graph", target)
		}
		if action.Mode == host.AccessGrant {
			for _, candidate := range candidates {
				if containsRecipient(plan.recipients, candidate.DeviceID()) {
					policyEvaluations++
					if err := execution.Report(host.PhasePolicy, host.ProgressUnitItems, policyEvaluations, uint64(len(targets)*len(candidates))); err != nil {
						return host.Outcome{}, err
					}
					continue
				}
				if err := evaluateGrantPolicy(ctx, policyEngine, policySource, state, openedPolicy, plan.source.Revision, candidate); err != nil {
					return host.Outcome{}, err
				}
				policyEvaluations++
				if err := execution.Report(host.PhasePolicy, host.ProgressUnitItems, policyEvaluations, uint64(len(targets)*len(candidates))); err != nil {
					return host.Outcome{}, err
				}
				plan.recipients = append(plan.recipients, candidate)
			}
			plan.rewrapOnly = true
		} else {
			remaining, err := removeRecipients(plan.recipients, candidates)
			if err != nil {
				return host.Outcome{}, fmt.Errorf("revoke access to %s: %w", target, err)
			}
			if !containsRecipient(remaining, state.device.DeviceID()) {
				return host.Outcome{}, errors.New("apphost: the publishing device cannot revoke its own access")
			}
			plan.recipients = remaining
			// Confidentiality narrowing is never represented by deleting a wrap.
			// Force a new Material identity and stream every byte through it.
			plan.forceSeal = true
		}
		sortRecipients(plan.recipients)
	}

	rootOpened, ok := graph.ByRevision[graph.Root.Revision]
	if !ok {
		return host.Outcome{}, errors.New("apphost: opened graph has no root revision")
	}
	if err := execution.Report(host.PhaseSealing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	builder := newGraphResealer(ctx, state, baseCommit.Policy, nodes)
	newRoot, err := builder.seal(rootOpened.Revision.UID)
	if err != nil {
		return host.Outcome{}, err
	}
	if newRoot == baseCommit.Root {
		return host.Outcome{}, errors.New("apphost: access operation produced no change")
	}

	if err := execution.Report(host.PhasePublishing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	if outcome, conflict, err := executor.recheckBaseFrontier(ctx, state, baseCommit, action.BaseCommit); err != nil {
		return host.Outcome{}, err
	} else if conflict {
		return outcome, nil
	}

	provenance := make([]commitmodel.MutationProvenance, 0, len(targets))
	changes := make([]host.ResourceChange, 0, len(targets))
	actionType, _ := artifact.ParseTypeRef("operations.enbu.net/v1alpha1/ChangeAccess")
	for _, target := range targets {
		plan := nodes[target]
		id, err := newUUID()
		if err != nil {
			return host.Outcome{}, err
		}
		before, after := plan.source.Ref, plan.result
		provenance = append(provenance, commitmodel.MutationProvenance{
			ID: id, Action: actionType, Target: target, Before: &before, After: &after,
		})
		changes = append(changes, host.ResourceChange{
			UID: target, Kind: host.ResourceUpdated, Before: before.Revision, After: after.Revision,
		})
	}
	rootRecipients := append([]artifact.VerifiedDevice(nil), nodes[rootOpened.Revision.UID].recipients...)
	closure := engine.MergeClosures(builder.closure(), closureForOpened(openedPolicy))
	if action.Mode == host.AccessGrant {
		// A new device must be able to authenticate the entire parent chain,
		// not only the newly published frontier. Publish immutable envelope
		// variants before the new child becomes visible. This is monotonic:
		// a retry may find the variants already present, but never narrows or
		// rewrites an existing Commit.
		if err := publishHistoryGrantVariants(ctx, state, discovery, candidates); err != nil {
			return host.Outcome{}, err
		}
	}
	published, err := (engine.Publisher{
		Local: state.objects, Remote: state.remote, Device: state.device, Author: state.author,
		Recipients: rootRecipients, Audit: state.audit, AuditExternallyManaged: true,
	}).Publish(ctx, engine.AuditActionChangeAccess, engine.CommitMutation{
		WorkspaceID: state.config.Workspace, Root: newRoot, Policy: baseCommit.Policy,
		Parents: []digest.Digest{action.BaseCommit}, Actor: state.author.Subject(), OperationID: execution.OperationID(),
		Provenance: provenance, Closure: closure,
	})
	if err != nil {
		return host.Outcome{}, err
	}
	return host.Outcome{Commit: &host.CommitResult{Commit: published.CommitID, Root: newRoot, Changes: changes}}, nil
}

func publishHistoryGrantVariants(
	ctx context.Context,
	state *workspaceState,
	discovery registry.Discovery,
	candidates []artifact.VerifiedDevice,
) error {
	recipients := append([]artifact.VerifiedDevice{state.author}, candidates...)
	sortRecipients(recipients)
	uniqueRecipients := recipients[:0]
	for _, recipient := range recipients {
		if len(uniqueRecipients) == 0 || uniqueRecipients[len(uniqueRecipients)-1].DeviceID() != recipient.DeviceID() {
			uniqueRecipients = append(uniqueRecipients, recipient)
		}
	}

	byCommit := make(map[digest.Digest]registry.VerifiedCommit, len(discovery.Announcements))
	for _, announcement := range discovery.Announcements {
		byCommit[announcement.Commit.CommitID] = announcement.Commit
	}
	commitIDs := make([]digest.Digest, 0, len(byCommit))
	for commitID := range byCommit {
		commitIDs = append(commitIDs, commitID)
	}
	sort.Slice(commitIDs, func(i, j int) bool { return commitIDs[i].String() < commitIDs[j].String() })
	source := fallbackSource{local: state.objects, remote: state.remote}
	for _, commitID := range commitIDs {
		verified := byCommit[commitID]
		grant, err := verified.RewrapAccessGrant(ctx, state.device, uniqueRecipients)
		if err != nil {
			return fmt.Errorf("rewrap history Commit %s: %w", commitID, err)
		}
		encoded, err := artifact.EncodeAccessGrant(grant)
		if err != nil {
			return err
		}
		grantDescriptor, err := state.objects.Ingest(ctx, artifact.MediaTypeAccessGrant, bytes.NewReader(encoded))
		wipeSensitive(encoded)
		if err != nil {
			return err
		}
		announcement, err := registry.NewCommitAnnouncement(
			state.config.Workspace,
			verified.CommitID,
			verified.EncryptedCommit,
			grantDescriptor,
			state.device,
			state.author,
		)
		if err != nil {
			return err
		}
		if _, err := registry.Publish(ctx, state.remote, source, registry.PublicationClosure{}, announcement); err != nil {
			return fmt.Errorf("publish history Commit %s envelope: %w", commitID, err)
		}
	}
	return nil
}

// expandGrantTargets adds every strong ancestor required to discover and open
// a requested Resource. It does not add siblings: their SealedRefs become
// visible from an ancestor, but their independent Grants remain unopened.
func expandGrantTargets(graph engine.Graph, requested []artifact.UUID) ([]artifact.UUID, error) {
	root, exists := graph.ByRevision[graph.Root.Revision]
	if !exists {
		return nil, errors.New("apphost: opened graph has no root revision")
	}
	parents := make(map[artifact.UUID][]artifact.UUID, len(graph.ByUID))
	for parentUID, opened := range graph.ByUID {
		for _, edge := range opened.Revision.Edges {
			if edge.Strength == artifact.EdgePinned {
				parents[edge.Target] = append(parents[edge.Target], parentUID)
			}
		}
	}
	selected := make(map[artifact.UUID]struct{}, len(requested)+1)
	for _, target := range requested {
		if _, exists := graph.ByUID[target]; !exists {
			return nil, fmt.Errorf("apphost: access target %s is not in the selected graph", target)
		}
		pending := []artifact.UUID{target}
		for len(pending) > 0 {
			current := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if _, seen := selected[current]; seen {
				continue
			}
			selected[current] = struct{}{}
			pending = append(pending, parents[current]...)
		}
	}
	if _, reachable := selected[root.Revision.UID]; !reachable {
		return nil, errors.New("apphost: access target has no strong path from root")
	}
	result := make([]artifact.UUID, 0, len(selected))
	for target := range selected {
		result = append(result, target)
	}
	return result, nil
}

func (executor *Executor) recheckBaseFrontier(
	ctx context.Context,
	state *workspaceState,
	base commitmodel.Commit,
	baseID digest.Digest,
) (host.Outcome, bool, error) {
	dag, err := executor.completeDAG(ctx, state)
	if err != nil {
		return host.Outcome{}, false, err
	}
	if dag == nil {
		return host.Outcome{}, false, commitmodel.ErrCommitNotFound
	}
	frontier := dag.Frontier()
	if len(frontier) == 1 && frontier[0] == baseID {
		return host.Outcome{}, false, nil
	}
	outcome, err := conflictForFrontier(base, baseID, frontier)
	return outcome, true, err
}

func collectKnownRecipients(
	ctx context.Context,
	graph engine.Graph,
	openedPolicy engine.OpenedRevision,
	state *workspaceState,
) (map[digest.Digest]artifact.VerifiedDevice, error) {
	result := make(map[digest.Digest]artifact.VerifiedDevice)
	opened := make([]engine.OpenedRevision, 0, len(graph.ByUID)+1)
	opened = append(opened, openedPolicy)
	for _, value := range graph.ByUID {
		opened = append(opened, value)
	}
	for _, value := range opened {
		for _, claim := range value.Grant.Claims.Recipients {
			verified, err := artifact.VerifyEnrollment(ctx, state.verifier, claim.Enrollment)
			if err != nil {
				return nil, err
			}
			if verified.AssertionDigest() != claim.EnrollmentDigest {
				return nil, errors.New("apphost: enrollment digest mismatch in known Grant")
			}
			if previous, exists := result[claim.EnrollmentDigest]; exists &&
				(previous.DeviceID() != verified.DeviceID() || previous.RecipientString() != verified.RecipientString()) {
				return nil, errors.New("apphost: ambiguous enrollment digest")
			}
			result[claim.EnrollmentDigest] = verified
		}
	}
	state.enrollmentMu.RLock()
	for enrollmentDigest, verified := range state.knownEnrollments {
		if existing, exists := result[enrollmentDigest]; exists && existing.DeviceID() != verified.DeviceID() {
			state.enrollmentMu.RUnlock()
			return nil, errors.New("apphost: ambiguous approved enrollment digest")
		}
		result[enrollmentDigest] = verified
	}
	state.enrollmentMu.RUnlock()
	return result, nil
}

func readPolicySource(ctx context.Context, source artifact.ObjectSource, opened engine.OpenedRevision) ([]byte, error) {
	if opened.Revision.Schema.String() != schema.SchemaRegoPolicy || len(opened.Revision.Payloads) != 1 {
		return nil, errors.New("apphost: pinned policy is not a single-stream RegoPolicy")
	}
	payload := opened.Revision.Payloads[0]
	if payload.Size <= 0 || payload.Size > policy.MaxPolicyBytes {
		return nil, errors.New("apphost: pinned policy exceeds source bounds")
	}
	var output bytes.Buffer
	output.Grow(int(payload.Size))
	if err := opened.WritePayload(ctx, source, payload.Name, &output); err != nil {
		return nil, err
	}
	value := output.Bytes()
	if int64(len(value)) != payload.Size {
		wipeSensitive(value)
		return nil, errors.New("apphost: pinned policy plaintext size mismatch")
	}
	if err := schema.ValidateRegoPolicy(value); err != nil {
		wipeSensitive(value)
		return nil, err
	}
	return value, nil
}

func evaluateGrantPolicy(
	ctx context.Context,
	policyEngine *policy.Engine,
	source []byte,
	state *workspaceState,
	openedPolicy engine.OpenedRevision,
	target artifact.Revision,
	candidate artifact.VerifiedDevice,
) error {
	policyRecipients, err := verifiedGrantRecipients(ctx, openedPolicy.Grant.Claims.Recipients, state.verifier)
	if err != nil {
		return err
	}
	var owner artifact.VerifiedDevice
	for _, recipient := range policyRecipients {
		if recipient.DeviceID() == openedPolicy.Grant.Claims.Issuer {
			if owner.DeviceID() != "" {
				return errors.New("apphost: policy Grant has ambiguous owner")
			}
			owner = recipient
		}
	}
	if owner.DeviceID() == "" {
		return errors.New("apphost: policy Grant has no verified owner")
	}
	_, err = policyEngine.Evaluate(ctx, source, policy.Input{
		Action:    "grant.add",
		Actor:     policy.Identity{Subject: state.author.Subject(), DeviceID: string(state.author.DeviceID()), Verified: true},
		Candidate: policy.Identity{Subject: candidate.Subject(), DeviceID: string(candidate.DeviceID()), Verified: true},
		Workspace: policy.Workspace{ID: string(state.config.Workspace), OwnerSubject: owner.Subject(), OwnerDevice: string(owner.DeviceID())},
		Target: policy.Target{
			UID: string(target.UID), Schema: target.Schema.String(), Labels: cloneStrings(target.Metadata.Labels),
			Annotations: cloneStrings(target.Metadata.Annotations),
		},
		PolicyDigest: openedPolicy.Ref.Revision.String(),
	})
	return err
}

func removeRecipients(current, candidates []artifact.VerifiedDevice) ([]artifact.VerifiedDevice, error) {
	remove := make(map[digest.Digest]struct{}, len(candidates))
	for _, candidate := range candidates {
		remove[candidate.AssertionDigest()] = struct{}{}
	}
	result := make([]artifact.VerifiedDevice, 0, len(current))
	removed := make(map[digest.Digest]struct{}, len(candidates))
	for _, recipient := range current {
		if _, exists := remove[recipient.AssertionDigest()]; exists {
			removed[recipient.AssertionDigest()] = struct{}{}
			continue
		}
		result = append(result, recipient)
	}
	if len(removed) != len(remove) {
		return nil, errors.New("one or more candidates do not currently have access")
	}
	if len(result) == 0 {
		return nil, errors.New("recipient set cannot become empty")
	}
	return result, nil
}

func wipeSensitive(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

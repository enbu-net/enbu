package apphost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/schema"
	"github.com/opencontainers/go-digest"
)

var errSemanticMergeConflict = errors.New("apphost: semantic merge conflict")

type mergePlanner struct {
	ctx         context.Context
	state       *workspaceState
	source      artifact.ObjectSource
	baseID      digest.Digest
	headIDs     []digest.Digest
	base        engine.Graph
	heads       []engine.Graph
	resolutions map[artifact.UUID]digest.Digest
	used        map[artifact.UUID]struct{}
	conflicts   []host.ConflictSummary
}

func (executor *Executor) merge(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	action host.MergeAction,
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
	heads := append([]digest.Digest(nil), action.Heads...)
	sort.Slice(heads, func(i, j int) bool { return heads[i].String() < heads[j].String() })
	frontier := dag.Frontier()
	if !equalDigests(heads, frontier) {
		return mergeFrontierConflict(state.config.Workspace, heads, frontier)
	}
	baseIDs, err := commonMergeBases(dag, heads)
	if err != nil {
		return host.Outcome{}, err
	}
	if len(baseIDs) != 1 {
		return ambiguousBaseConflict(state.config.Workspace, heads, baseIDs)
	}
	baseID := baseIDs[0]
	baseCommit, _ := dag.Commit(baseID)
	headCommits := make([]commitmodel.Commit, 0, len(heads))
	for _, head := range heads {
		value, ok := dag.Commit(head)
		if !ok {
			return host.Outcome{}, fmt.Errorf("%w: %s", commitmodel.ErrCommitNotFound, head)
		}
		headCommits = append(headCommits, value)
	}
	if err := executor.beginFinalization(ctx, state.audit, execution.OperationID(), engine.AuditActionMerge, baseCommit.Root.Material); err != nil {
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
	headGraphs := make([]engine.Graph, 0, len(headCommits))
	for _, value := range headCommits {
		graph, openErr := engine.OpenGraph(ctx, objectSource, state.device, state.verifier, value.Root)
		if openErr != nil {
			return host.Outcome{}, openErr
		}
		headGraphs = append(headGraphs, graph)
	}

	planner := &mergePlanner{
		ctx: ctx, state: state, source: objectSource, baseID: baseID, headIDs: heads,
		base: baseGraph, heads: headGraphs, resolutions: make(map[artifact.UUID]digest.Digest), used: make(map[artifact.UUID]struct{}),
	}
	for _, resolution := range action.Resolutions {
		planner.resolutions[resolution.ConflictID] = resolution.SelectCommit
	}
	selectedPolicy, openedPolicy, err := planner.mergePolicy(baseCommit, headCommits)
	if err != nil {
		return host.Outcome{}, err
	}
	if len(planner.conflicts) != 0 {
		return host.Outcome{Conflict: &host.ConflictResult{Conflicts: planner.conflicts}}, nil
	}
	if selectedPolicy != baseCommit.Policy && mergeChangesRecipientSets(baseGraph, headGraphs) {
		root := baseGraph.ByRevision[baseGraph.Root.Revision]
		policyRevisions := make([]digest.Digest, 0, len(headCommits))
		for _, value := range headCommits {
			policyRevisions = append(policyRevisions, value.Policy.Revision)
		}
		conflict := host.ConflictSummary{
			ID:     deterministicConflictID(host.ConflictPolicy, root.Revision.UID, baseCommit.Policy.Revision, policyRevisions, "policy-access"),
			Target: root.Revision.UID, Schema: openedPolicy.Revision.Schema, Kind: host.ConflictPolicy,
			Base: baseCommit.Policy.Revision, Ours: selectedPolicy.Revision,
		}
		return host.Outcome{Conflict: &host.ConflictResult{Conflicts: []host.ConflictSummary{conflict}}}, nil
	}

	nodes, err := planner.planNodes()
	if err != nil {
		return host.Outcome{}, err
	}
	if len(planner.conflicts) != 0 {
		return host.Outcome{Conflict: &host.ConflictResult{Conflicts: planner.conflicts}}, nil
	}
	for conflictID := range planner.resolutions {
		if _, used := planner.used[conflictID]; !used {
			return host.Outcome{}, fmt.Errorf("apphost: conflict resolution %s does not match this merge", conflictID)
		}
	}
	baseRoot := baseGraph.ByRevision[baseGraph.Root.Revision]
	if baseRoot.Revision.UID == "" {
		return host.Outcome{}, errors.New("apphost: merge base has no root")
	}
	for _, graph := range headGraphs {
		root := graph.ByRevision[graph.Root.Revision]
		if root.Revision.UID != baseRoot.Revision.UID {
			return host.Outcome{}, errors.New("apphost: merge heads have different workspace roots")
		}
	}
	if nodes[baseRoot.Revision.UID] == nil {
		return host.Outcome{}, errors.New("apphost: merge deleted the workspace root")
	}

	if err := execution.Report(host.PhaseSealing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	builder := newGraphResealer(ctx, state, selectedPolicy, nodes)
	newRoot, err := builder.seal(baseRoot.Revision.UID)
	if err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhasePublishing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	latestDAG, err := executor.completeDAG(ctx, state)
	if err != nil {
		return host.Outcome{}, err
	}
	if latestDAG == nil {
		return host.Outcome{}, commitmodel.ErrCommitNotFound
	}
	if latestFrontier := latestDAG.Frontier(); !equalDigests(heads, latestFrontier) {
		return mergeFrontierConflict(state.config.Workspace, heads, latestFrontier)
	}

	provenanceID, err := newUUID()
	if err != nil {
		return host.Outcome{}, err
	}
	actionType, _ := artifact.ParseTypeRef("operations.enbu.net/v1alpha1/Merge")
	inputs := make([]commitmodel.PinnedInput, 0, len(heads)+1)
	baseRole, _ := artifact.ParseTypeRef("inputs.enbu.net/v1alpha1/Base")
	inputs = append(inputs, commitmodel.PinnedInput{Role: baseRole, UID: baseRoot.Revision.UID, Sealed: baseCommit.Root})
	for index, value := range headCommits {
		role, _ := artifact.ParseTypeRef("inputs.enbu.net/v1alpha1/Head" + strconv.Itoa(index+1))
		inputs = append(inputs, commitmodel.PinnedInput{Role: role, UID: baseRoot.Revision.UID, Sealed: value.Root})
	}
	after := newRoot
	provenance := []commitmodel.MutationProvenance{{
		ID: provenanceID, Action: actionType, Target: baseRoot.Revision.UID, After: &after, Inputs: inputs,
	}}
	changes := mergeResultChanges(baseGraph, nodes, baseRoot.Revision.UID)
	closure := engine.MergeClosures(builder.closure(), closureForOpened(openedPolicy))
	published, err := (engine.Publisher{
		Local: state.objects, Remote: state.remote, Device: state.device, Author: state.author,
		Recipients: append([]artifact.VerifiedDevice(nil), nodes[baseRoot.Revision.UID].recipients...), Audit: state.audit, AuditExternallyManaged: true,
	}).Publish(ctx, engine.AuditActionMerge, engine.CommitMutation{
		WorkspaceID: state.config.Workspace, Root: newRoot, Policy: selectedPolicy,
		Parents: heads, Actor: state.author.Subject(), OperationID: execution.OperationID(),
		Provenance: provenance, Closure: closure,
	})
	if err != nil {
		return host.Outcome{}, err
	}
	return host.Outcome{Commit: &host.CommitResult{Commit: published.CommitID, Root: newRoot, Changes: changes}}, nil
}

// mergeChangesRecipientSets rejects policy and access changes in the same
// merge. Otherwise a recipient admitted under an old policy could be copied
// into a Grant that claims the newly selected, stricter policy without ever
// being evaluated by that policy.
func mergeChangesRecipientSets(base engine.Graph, heads []engine.Graph) bool {
	for _, head := range heads {
		if len(head.ByUID) != len(base.ByUID) {
			return true
		}
		for uid, baseOpened := range base.ByUID {
			headOpened, exists := head.ByUID[uid]
			if !exists || grantRecipientSetKey(baseOpened.Grant.Claims.Recipients) != grantRecipientSetKey(headOpened.Grant.Claims.Recipients) {
				return true
			}
		}
	}
	return false
}

func (planner *mergePlanner) mergePolicy(base commitmodel.Commit, heads []commitmodel.Commit) (artifact.SealedRef, engine.OpenedRevision, error) {
	references := make([]artifact.SealedRef, len(heads))
	for index := range heads {
		references[index] = heads[index].Policy
	}
	selected, conflict := selectSealedRef(base.Policy, references)
	if conflict {
		openedBase, err := engine.OpenRevision(planner.ctx, planner.source, planner.state.device, planner.state.verifier, base.Policy)
		if err != nil {
			return artifact.SealedRef{}, engine.OpenedRevision{}, err
		}
		selectedHead, resolved := planner.resolveConflict(
			host.ConflictPolicy, openedBase.Revision.UID, openedBase.Revision.Schema, "policy",
			base.Policy.Revision, revisionDigests(references),
		)
		if !resolved {
			return artifact.SealedRef{}, engine.OpenedRevision{}, nil
		}
		selected = references[selectedHead]
	}
	opened, err := engine.OpenRevision(planner.ctx, planner.source, planner.state.device, planner.state.verifier, selected)
	if err != nil {
		return artifact.SealedRef{}, engine.OpenedRevision{}, err
	}
	return selected, opened, nil
}

func (planner *mergePlanner) planNodes() (map[artifact.UUID]*revisionPlan, error) {
	uids := make(map[artifact.UUID]struct{}, len(planner.base.ByUID))
	for uid := range planner.base.ByUID {
		uids[uid] = struct{}{}
	}
	for _, graph := range planner.heads {
		for uid := range graph.ByUID {
			uids[uid] = struct{}{}
		}
	}
	ordered := make([]artifact.UUID, 0, len(uids))
	for uid := range uids {
		ordered = append(ordered, uid)
	}
	sort.Slice(ordered, func(i, j int) bool { return string(ordered[i]) < string(ordered[j]) })
	result := make(map[artifact.UUID]*revisionPlan, len(ordered))
	for _, uid := range ordered {
		plan, exists, err := planner.planNode(uid)
		if err != nil {
			return nil, err
		}
		if exists && plan != nil {
			result[uid] = plan
		}
	}
	return result, nil
}

func (planner *mergePlanner) planNode(uid artifact.UUID) (*revisionPlan, bool, error) {
	base, baseExists := planner.base.ByUID[uid]
	headValues := make([]engine.OpenedRevision, len(planner.heads))
	present := make([]bool, len(planner.heads))
	for index := range planner.heads {
		headValues[index], present[index] = planner.heads[index].ByUID[uid]
	}
	schemaRef := base.Revision.Schema
	if !baseExists {
		for index := range headValues {
			if present[index] {
				schemaRef = headValues[index].Revision.Schema
				break
			}
		}
	}

	if !baseExists {
		indices := presentIndices(present)
		if len(indices) == 0 {
			return nil, false, nil
		}
		chosen := indices[0]
		for _, index := range indices[1:] {
			if !sameRevisionSemantics(headValues[chosen].Revision, headValues[index].Revision) ||
				grantRecipientSetKey(headValues[chosen].Grant.Claims.Recipients) != grantRecipientSetKey(headValues[index].Grant.Claims.Recipients) {
				selected, resolved := planner.resolveConflict(host.ConflictConcurrentChange, uid, schemaRef, "concurrent-create", "", openedRevisionDigests(headValues, present))
				if !resolved {
					return nil, false, nil
				}
				if !present[selected] {
					return nil, false, nil
				}
				chosen = selected
				break
			}
		}
		recipients, err := verifiedGrantRecipients(planner.ctx, headValues[chosen].Grant.Claims.Recipients, planner.state.verifier)
		if err != nil {
			return nil, false, err
		}
		return revisionPlanFromOpened(headValues[chosen], recipients), true, nil
	}

	missing := 0
	for _, exists := range present {
		if !exists {
			missing++
		}
	}
	if missing != 0 {
		changed := false
		for index := range headValues {
			if present[index] && headValues[index].Ref != base.Ref {
				changed = true
				break
			}
		}
		if changed {
			selected, resolved := planner.resolveConflict(host.ConflictUpdateDelete, uid, schemaRef, "update-delete", base.Ref.Revision, openedRevisionDigests(headValues, present))
			if !resolved || !present[selected] {
				return nil, false, nil
			}
			recipients, err := verifiedGrantRecipients(planner.ctx, headValues[selected].Grant.Claims.Recipients, planner.state.verifier)
			if err != nil {
				return nil, false, err
			}
			return revisionPlanFromOpened(headValues[selected], recipients), true, nil
		}
		return nil, false, nil
	}

	contentSource := base
	contentRevision := cloneRevision(base.Revision)
	payloads := payloadPlansFromOpened(base)
	forceSeal := false
	changedSemantics := uniqueSemanticChanges(base.Revision, headValues)
	if len(changedSemantics) == 1 {
		contentSource = headValues[changedSemantics[0]]
		contentRevision = cloneRevision(contentSource.Revision)
		payloads = payloadPlansFromOpened(contentSource)
	} else if len(changedSemantics) > 1 {
		switch {
		case base.Revision.Kind == artifact.KindCollection && allCollections(headValues):
			merged, mergeErr := mergeCollectionRevision(base.Revision, revisionsOf(headValues))
			if mergeErr == nil {
				contentRevision = merged
				payloads = nil
				forceSeal = true
				break
			}
			if !errors.Is(mergeErr, errSemanticMergeConflict) {
				return nil, false, mergeErr
			}
			fallthrough
		case base.Revision.Schema.String() == schema.SchemaSecretMap && allSchema(headValues, schema.SchemaSecretMap):
			if base.Revision.Kind == artifact.KindResource && allResources(headValues) {
				merged, mergedPayload, mergeErr := planner.mergeSecretMap(base, headValues)
				if mergeErr == nil {
					contentRevision = merged
					payloads = []payloadPlan{mergedPayload}
					forceSeal = true
					break
				}
				if !errors.Is(mergeErr, errSemanticMergeConflict) {
					return nil, false, mergeErr
				}
			}
			fallthrough
		default:
			selected, resolved := planner.resolveConflict(host.ConflictConcurrentChange, uid, schemaRef, "content", base.Ref.Revision, openedRevisionDigests(headValues, present))
			if !resolved {
				return nil, false, nil
			}
			contentSource = headValues[selected]
			contentRevision = cloneRevision(contentSource.Revision)
			payloads = payloadPlansFromOpened(contentSource)
		}
	}

	baseRecipients, err := verifiedGrantRecipients(planner.ctx, base.Grant.Claims.Recipients, planner.state.verifier)
	if err != nil {
		return nil, false, err
	}
	desiredRecipients := baseRecipients
	recipientChanges := uniqueRecipientChanges(base, headValues)
	if len(recipientChanges) == 1 {
		desiredRecipients, err = verifiedGrantRecipients(planner.ctx, headValues[recipientChanges[0]].Grant.Claims.Recipients, planner.state.verifier)
	} else if len(recipientChanges) > 1 {
		selected, resolved := planner.resolveConflict(host.ConflictAccess, uid, schemaRef, "access", base.Ref.Grant, openedGrantDigests(headValues))
		if !resolved {
			return nil, false, nil
		}
		desiredRecipients, err = verifiedGrantRecipients(planner.ctx, headValues[selected].Grant.Claims.Recipients, planner.state.verifier)
	}
	if err != nil {
		return nil, false, err
	}
	sortRecipients(desiredRecipients)
	sourceCopy := contentSource
	return &revisionPlan{
		revision: contentRevision, payloads: payloads, recipients: desiredRecipients,
		source: &sourceCopy, forceSeal: forceSeal,
	}, true, nil
}

func (planner *mergePlanner) mergeSecretMap(base engine.OpenedRevision, heads []engine.OpenedRevision) (artifact.Revision, payloadPlan, error) {
	values := make([]schema.SecretMap, len(heads)+1)
	opened := append([]engine.OpenedRevision{base}, heads...)
	for index, value := range opened {
		if len(value.Revision.Payloads) != 1 {
			return artifact.Revision{}, payloadPlan{}, errSemanticMergeConflict
		}
		if index != 0 && (value.Revision.Payloads[0].Name != base.Revision.Payloads[0].Name || value.Revision.Payloads[0].MediaType != base.Revision.Payloads[0].MediaType) {
			return artifact.Revision{}, payloadPlan{}, errSemanticMergeConflict
		}
		encoded, err := readPayloadBounded(planner.ctx, planner.source, value, value.Revision.Payloads[0].Name, schema.MaxOpaqueBytes)
		if err != nil {
			return artifact.Revision{}, payloadPlan{}, err
		}
		values[index], err = schema.DecodeSecretMap(encoded)
		wipeSensitive(encoded)
		if err != nil {
			return artifact.Revision{}, payloadPlan{}, err
		}
	}
	mergedValues, err := mergeSecretValues(values[0], values[1:])
	if err != nil {
		return artifact.Revision{}, payloadPlan{}, err
	}
	encoded, err := schema.EncodeSecretMap(mergedValues)
	if err != nil {
		return artifact.Revision{}, payloadPlan{}, err
	}
	mergedRevision, err := mergeRevisionEnvelope(base.Revision, revisionsOf(heads))
	if err != nil {
		wipeSensitive(encoded)
		return artifact.Revision{}, payloadPlan{}, err
	}
	payload := base.Revision.Payloads[0]
	return mergedRevision, fixedPayloadPlan(payload.Name, payload.MediaType, encoded), nil
}

func (planner *mergePlanner) resolveConflict(
	kind host.ConflictKind,
	target artifact.UUID,
	schemaRef artifact.TypeRef,
	detail string,
	base digest.Digest,
	variants []digest.Digest,
) (int, bool) {
	id := deterministicConflictID(kind, target, planner.baseID, planner.headIDs, detail)
	if selectedCommit, exists := planner.resolutions[id]; exists {
		for index, head := range planner.headIDs {
			if head == selectedCommit {
				planner.used[id] = struct{}{}
				return index, true
			}
		}
	}
	ours, theirs := digest.Digest(""), digest.Digest("")
	if len(variants) > 0 {
		ours = variants[0]
	}
	if len(variants) > 1 {
		theirs = variants[1]
	}
	planner.conflicts = append(planner.conflicts, host.ConflictSummary{
		ID: id, Target: target, Schema: schemaRef, Kind: kind, Base: base, Ours: ours, Theirs: theirs,
	})
	return 0, false
}

func commonMergeBases(dag *commitmodel.DAG, heads []digest.Digest) ([]digest.Digest, error) {
	if dag == nil || len(heads) < 2 {
		return nil, errors.New("apphost: merge needs a verified DAG and at least two heads")
	}
	common := make(map[digest.Digest]struct{})
	first, err := dag.ReachableFrom(heads[0])
	if err != nil {
		return nil, err
	}
	for _, value := range first {
		common[value] = struct{}{}
	}
	for _, head := range heads[1:] {
		reachable, err := dag.ReachableFrom(head)
		if err != nil {
			return nil, err
		}
		set := make(map[digest.Digest]struct{}, len(reachable))
		for _, value := range reachable {
			set[value] = struct{}{}
		}
		for candidate := range common {
			if _, exists := set[candidate]; !exists {
				delete(common, candidate)
			}
		}
	}
	notBest := make(map[digest.Digest]struct{})
	for child := range common {
		value, _ := dag.Commit(child)
		for _, parent := range value.Parents {
			if _, exists := common[parent]; exists {
				notBest[parent] = struct{}{}
			}
		}
	}
	result := make([]digest.Digest, 0, len(common))
	for candidate := range common {
		if _, inferior := notBest[candidate]; !inferior {
			result = append(result, candidate)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].String() < result[j].String() })
	return result, nil
}

func mergeCollectionRevision(base artifact.Revision, heads []artifact.Revision) (artifact.Revision, error) {
	if base.Kind != artifact.KindCollection {
		return artifact.Revision{}, errSemanticMergeConflict
	}
	merged, err := mergeRevisionEnvelope(base, heads)
	if err != nil {
		return artifact.Revision{}, err
	}
	merged.Payloads = nil
	return merged, nil
}

func mergeRevisionEnvelope(base artifact.Revision, heads []artifact.Revision) (artifact.Revision, error) {
	for _, value := range heads {
		if value.Kind != base.Kind || value.UID != base.UID || value.Schema != base.Schema {
			return artifact.Revision{}, errSemanticMergeConflict
		}
	}
	metadata := make([]artifact.Metadata, len(heads))
	for index := range heads {
		metadata[index] = heads[index].Metadata
	}
	mergedMetadata, ok := selectMetadata(base.Metadata, metadata)
	if !ok {
		return artifact.Revision{}, errSemanticMergeConflict
	}
	mergedEdges, err := mergeEdges(base.Edges, edgesOf(heads))
	if err != nil {
		return artifact.Revision{}, err
	}
	merged := cloneRevision(base)
	merged.Metadata = mergedMetadata
	merged.Edges = mergedEdges
	return merged, nil
}

func mergeEdges(base []artifact.Edge, heads [][]artifact.Edge) ([]artifact.Edge, error) {
	baseByID := edgeMap(base)
	headByID := make([]map[artifact.UUID]artifact.Edge, len(heads))
	ids := make(map[artifact.UUID]struct{}, len(base))
	for id := range baseByID {
		ids[id] = struct{}{}
	}
	for index := range heads {
		headByID[index] = edgeMap(heads[index])
		for id := range headByID[index] {
			ids[id] = struct{}{}
		}
	}
	ordered := make([]artifact.UUID, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Slice(ordered, func(i, j int) bool { return string(ordered[i]) < string(ordered[j]) })
	result := make([]artifact.Edge, 0, len(ordered))
	for _, id := range ordered {
		baseValue, basePresent := baseByID[id]
		changed := make([]optionalEdge, 0, len(heads))
		for index := range heads {
			value, present := headByID[index][id]
			candidate := optionalEdge{present: present, value: normalizeEdge(value)}
			original := optionalEdge{present: basePresent, value: normalizeEdge(baseValue)}
			if !reflect.DeepEqual(candidate, original) && !containsOptionalEdge(changed, candidate) {
				changed = append(changed, candidate)
			}
		}
		if len(changed) > 1 {
			return nil, errSemanticMergeConflict
		}
		if len(changed) == 0 {
			if basePresent {
				result = append(result, cloneEdge(baseValue))
			}
			continue
		}
		if !changed[0].present {
			continue
		}
		for index := range heads {
			value, present := headByID[index][id]
			if present && reflect.DeepEqual(normalizeEdge(value), changed[0].value) {
				result = append(result, cloneEdge(value))
				break
			}
		}
	}
	return result, nil
}

type optionalEdge struct {
	present bool
	value   artifact.Edge
}

func mergeSecretValues(base schema.SecretMap, heads []schema.SecretMap) (schema.SecretMap, error) {
	keys := make(map[string]struct{}, len(base))
	for key := range base {
		keys[key] = struct{}{}
	}
	for _, values := range heads {
		for key := range values {
			keys[key] = struct{}{}
		}
	}
	result := make(schema.SecretMap, len(keys))
	for key := range keys {
		baseValue, basePresent := base[key]
		changed := make([]optionalString, 0, len(heads))
		for _, values := range heads {
			value, present := values[key]
			candidate := optionalString{present: present, value: value}
			if candidate != (optionalString{present: basePresent, value: baseValue}) && !containsOptionalString(changed, candidate) {
				changed = append(changed, candidate)
			}
		}
		if len(changed) > 1 {
			return nil, errSemanticMergeConflict
		}
		selected := optionalString{present: basePresent, value: baseValue}
		if len(changed) == 1 {
			selected = changed[0]
		}
		if selected.present {
			result[key] = selected.value
		}
	}
	return result, result.Validate()
}

type optionalString struct {
	present bool
	value   string
}

func selectSealedRef(base artifact.SealedRef, heads []artifact.SealedRef) (artifact.SealedRef, bool) {
	changed := make([]artifact.SealedRef, 0, len(heads))
	for _, value := range heads {
		if value != base && !containsSealedRef(changed, value) {
			changed = append(changed, value)
		}
	}
	if len(changed) == 0 {
		return base, false
	}
	if len(changed) == 1 {
		return changed[0], false
	}
	return artifact.SealedRef{}, true
}

func uniqueSemanticChanges(base artifact.Revision, heads []engine.OpenedRevision) []int {
	result := make([]int, 0, len(heads))
	for index := range heads {
		if sameRevisionSemantics(base, heads[index].Revision) {
			continue
		}
		duplicate := false
		for _, previous := range result {
			if sameRevisionSemantics(heads[previous].Revision, heads[index].Revision) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, index)
		}
	}
	return result
}

func uniqueRecipientChanges(base engine.OpenedRevision, heads []engine.OpenedRevision) []int {
	baseKey := grantRecipientSetKey(base.Grant.Claims.Recipients)
	result := make([]int, 0, len(heads))
	for index := range heads {
		key := grantRecipientSetKey(heads[index].Grant.Claims.Recipients)
		if key == baseKey {
			continue
		}
		duplicate := false
		for _, previous := range result {
			if grantRecipientSetKey(heads[previous].Grant.Claims.Recipients) == key {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, index)
		}
	}
	return result
}

func sameRevisionSemantics(left, right artifact.Revision) bool {
	return reflect.DeepEqual(normalizeRevision(left), normalizeRevision(right))
}

func normalizeRevision(value artifact.Revision) artifact.Revision {
	copy := cloneRevision(value)
	for index := range copy.Edges {
		if copy.Edges[index].Strength == artifact.EdgePinned {
			copy.Edges[index].Pinned = nil
		}
	}
	return copy
}

func normalizeEdge(value artifact.Edge) artifact.Edge {
	copy := cloneEdge(value)
	if copy.Strength == artifact.EdgePinned {
		copy.Pinned = nil
	}
	return copy
}

func cloneEdge(value artifact.Edge) artifact.Edge {
	if value.Pinned != nil {
		pinned := *value.Pinned
		value.Pinned = &pinned
	}
	return value
}

func edgeMap(values []artifact.Edge) map[artifact.UUID]artifact.Edge {
	result := make(map[artifact.UUID]artifact.Edge, len(values))
	for _, value := range values {
		result[value.ID] = value
	}
	return result
}

func selectMetadata(base artifact.Metadata, heads []artifact.Metadata) (artifact.Metadata, bool) {
	changed := make([]artifact.Metadata, 0, len(heads))
	for _, value := range heads {
		if reflect.DeepEqual(value, base) {
			continue
		}
		duplicate := false
		for _, previous := range changed {
			if reflect.DeepEqual(previous, value) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			changed = append(changed, value)
		}
	}
	if len(changed) > 1 {
		return artifact.Metadata{}, false
	}
	if len(changed) == 0 {
		return cloneMetadataForReseal(base), true
	}
	return cloneMetadataForReseal(changed[0]), true
}

func readPayloadBounded(ctx context.Context, source artifact.ObjectSource, opened engine.OpenedRevision, name string, limit int) ([]byte, error) {
	var expected int64 = -1
	for _, payload := range opened.Revision.Payloads {
		if payload.Name == name {
			expected = payload.Size
			break
		}
	}
	if expected < 0 || expected > int64(limit) {
		return nil, errors.New("apphost: merge payload exceeds semantic codec bounds")
	}
	var output bytes.Buffer
	output.Grow(int(expected))
	if err := opened.WritePayload(ctx, source, name, &output); err != nil {
		return nil, err
	}
	if int64(output.Len()) != expected {
		wipeSensitive(output.Bytes())
		return nil, errors.New("apphost: merge payload plaintext size mismatch")
	}
	return output.Bytes(), nil
}

func mergeResultChanges(base engine.Graph, nodes map[artifact.UUID]*revisionPlan, root artifact.UUID) []host.ResourceChange {
	uids := make(map[artifact.UUID]struct{}, len(base.ByUID)+len(nodes))
	for uid := range base.ByUID {
		uids[uid] = struct{}{}
	}
	for uid, plan := range nodes {
		if plan.done {
			uids[uid] = struct{}{}
		}
	}
	ordered := make([]artifact.UUID, 0, len(uids))
	for uid := range uids {
		ordered = append(ordered, uid)
	}
	sort.Slice(ordered, func(i, j int) bool { return string(ordered[i]) < string(ordered[j]) })
	result := make([]host.ResourceChange, 0, len(ordered))
	for _, uid := range ordered {
		before, beforeExists := base.ByUID[uid]
		plan, afterExists := nodes[uid]
		afterExists = afterExists && plan.done
		switch {
		case !beforeExists && afterExists:
			result = append(result, host.ResourceChange{UID: uid, Kind: host.ResourceCreated, After: plan.result.Revision})
		case beforeExists && !afterExists:
			result = append(result, host.ResourceChange{UID: uid, Kind: host.ResourceDeleted, Before: before.Ref.Revision})
		case beforeExists && afterExists && before.Ref != plan.result:
			result = append(result, host.ResourceChange{UID: uid, Kind: host.ResourceUpdated, Before: before.Ref.Revision, After: plan.result.Revision})
		}
	}
	if len(result) > host.MaxResultChanges {
		before := base.ByUID[root]
		return []host.ResourceChange{{UID: root, Kind: host.ResourceUpdated, Before: before.Ref.Revision, After: nodes[root].result.Revision}}
	}
	return result
}

func deterministicConflictID(kind host.ConflictKind, target artifact.UUID, base digest.Digest, heads []digest.Digest, detail string) artifact.UUID {
	var input strings.Builder
	input.WriteString("enbu.net/merge-conflict/v1\x00")
	input.WriteString(string(kind))
	input.WriteByte(0)
	input.WriteString(string(target))
	input.WriteByte(0)
	input.WriteString(base.String())
	input.WriteByte(0)
	for _, head := range heads {
		input.WriteString(head.String())
		input.WriteByte(0)
	}
	input.WriteString(detail)
	sum := sha256.Sum256([]byte(input.String()))
	raw := append([]byte(nil), sum[:16]...)
	raw[6] = raw[6]&0x0f | 0x50
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	value, _ := artifact.ParseUUID(encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:])
	return value
}

func mergeFrontierConflict(workspaceID artifact.UUID, expected, actual []digest.Digest) (host.Outcome, error) {
	base := digest.Digest("")
	if len(expected) > 0 {
		base = expected[0]
	}
	ours, theirs := digest.Digest(""), digest.Digest("")
	if len(expected) > 1 {
		ours = expected[1]
	}
	if len(actual) > 0 {
		theirs = actual[0]
	}
	id := deterministicConflictID(host.ConflictConcurrentChange, workspaceID, base, actual, "frontier")
	return host.Outcome{Conflict: &host.ConflictResult{Conflicts: []host.ConflictSummary{{
		ID: id, Target: workspaceID, Schema: workspaceSchema(), Kind: host.ConflictConcurrentChange,
		Base: base, Ours: ours, Theirs: theirs,
	}}}}, nil
}

func ambiguousBaseConflict(workspaceID artifact.UUID, heads, bases []digest.Digest) (host.Outcome, error) {
	base := digest.Digest("")
	if len(bases) > 0 {
		base = bases[0]
	}
	id := deterministicConflictID(host.ConflictConcurrentChange, workspaceID, base, heads, "ambiguous-base")
	ours, theirs := digest.Digest(""), digest.Digest("")
	if len(heads) > 0 {
		ours = heads[0]
	}
	if len(heads) > 1 {
		theirs = heads[1]
	}
	return host.Outcome{Conflict: &host.ConflictResult{Conflicts: []host.ConflictSummary{{
		ID: id, Target: workspaceID, Schema: workspaceSchema(), Kind: host.ConflictConcurrentChange,
		Base: base, Ours: ours, Theirs: theirs,
	}}}}, nil
}

func equalDigests(left, right []digest.Digest) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func revisionsOf(values []engine.OpenedRevision) []artifact.Revision {
	result := make([]artifact.Revision, len(values))
	for index := range values {
		result[index] = values[index].Revision
	}
	return result
}

func edgesOf(values []artifact.Revision) [][]artifact.Edge {
	result := make([][]artifact.Edge, len(values))
	for index := range values {
		result[index] = values[index].Edges
	}
	return result
}

func presentIndices(values []bool) []int {
	var result []int
	for index, value := range values {
		if value {
			result = append(result, index)
		}
	}
	return result
}

func openedRevisionDigests(values []engine.OpenedRevision, present []bool) []digest.Digest {
	result := make([]digest.Digest, len(values))
	for index := range values {
		if present[index] {
			result[index] = values[index].Ref.Revision
		}
	}
	return result
}

func openedGrantDigests(values []engine.OpenedRevision) []digest.Digest {
	result := make([]digest.Digest, len(values))
	for index := range values {
		result[index] = values[index].Ref.Grant
	}
	return result
}

func revisionDigests(values []artifact.SealedRef) []digest.Digest {
	result := make([]digest.Digest, len(values))
	for index := range values {
		result[index] = values[index].Revision
	}
	return result
}

func allCollections(values []engine.OpenedRevision) bool {
	for _, value := range values {
		if value.Revision.Kind != artifact.KindCollection {
			return false
		}
	}
	return true
}

func allResources(values []engine.OpenedRevision) bool {
	for _, value := range values {
		if value.Revision.Kind != artifact.KindResource {
			return false
		}
	}
	return true
}

func allSchema(values []engine.OpenedRevision, expected string) bool {
	for _, value := range values {
		if value.Revision.Schema.String() != expected {
			return false
		}
	}
	return true
}

func containsSealedRef(values []artifact.SealedRef, target artifact.SealedRef) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsOptionalEdge(values []optionalEdge, target optionalEdge) bool {
	for _, value := range values {
		if reflect.DeepEqual(value, target) {
			return true
		}
	}
	return false
}

func containsOptionalString(values []optionalString, target optionalString) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

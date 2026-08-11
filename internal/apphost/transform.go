package apphost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/schema"
	"github.com/opencontainers/go-digest"
)

func (executor *Executor) transform(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	action host.TransformAction,
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
	if err := executor.beginFinalization(ctx, state.audit, execution.OperationID(), engine.AuditActionTransform, baseCommit.Root.Material); err != nil {
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
	selectedInputs, err := exactTransformInputs(graph, action.Inputs)
	if err != nil {
		return host.Outcome{}, err
	}
	nodes, err := transformRevisionPlans(ctx, graph, state.verifier)
	if err != nil {
		return host.Outcome{}, err
	}
	if err := validateTransformPlacements(nodes, action.Outputs); err != nil {
		return host.Outcome{}, err
	}

	if err := execution.Report(host.PhaseTransforming, host.ProgressUnitItems, 0, uint64(len(action.Outputs))); err != nil {
		return host.Outcome{}, err
	}
	var outputs []engine.SealedRevision
	if action.Transform.Plugin != "" {
		outputs, err = executor.runPluginTransform(ctx, state, source, openedPolicy, selectedInputs, action)
	} else {
		outputs, err = runBuiltinTransform(ctx, execution, state, nodes, baseCommit.Policy, action)
	}
	if err != nil {
		return host.Outcome{}, err
	}
	if err := attachTransformOutputs(nodes, action.Outputs, outputs); err != nil {
		return host.Outcome{}, err
	}
	if err := execution.Report(host.PhaseTransforming, host.ProgressUnitItems, uint64(len(action.Outputs)), uint64(len(action.Outputs))); err != nil {
		return host.Outcome{}, err
	}

	rootOpened, ok := graph.ByRevision[graph.Root.Revision]
	if !ok {
		return host.Outcome{}, errors.New("apphost: transform graph has no root")
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
		return host.Outcome{}, errors.New("apphost: transform produced no graph change")
	}
	if err := execution.Report(host.PhasePublishing, host.ProgressUnitNone, 0, 0); err != nil {
		return host.Outcome{}, err
	}
	if outcome, conflict, err := executor.recheckBaseFrontier(ctx, state, baseCommit, action.BaseCommit); err != nil {
		return host.Outcome{}, err
	} else if conflict {
		return outcome, nil
	}

	provenance, changes, err := transformProvenance(action, nodes)
	if err != nil {
		return host.Outcome{}, err
	}
	closure := engine.MergeClosures(builder.closure(), closureForOpened(openedPolicy))
	published, err := (engine.Publisher{
		Local: state.objects, Remote: state.remote, Device: state.device, Author: state.author,
		Recipients: append([]artifact.VerifiedDevice(nil), nodes[rootOpened.Revision.UID].recipients...),
		Audit:      state.audit, AuditExternallyManaged: true,
	}).Publish(ctx, engine.AuditActionTransform, engine.CommitMutation{
		WorkspaceID: state.config.Workspace, Root: newRoot, Policy: baseCommit.Policy,
		Parents: []digest.Digest{action.BaseCommit}, Actor: state.author.Subject(), OperationID: execution.OperationID(),
		Provenance: provenance, Closure: closure,
	})
	if err != nil {
		return host.Outcome{}, err
	}
	return host.Outcome{Commit: &host.CommitResult{Commit: published.CommitID, Root: newRoot, Changes: changes}}, nil
}

func exactTransformInputs(graph engine.Graph, inputs []host.PinnedInput) ([]engine.PluginInputSelection, error) {
	selected := make([]engine.PluginInputSelection, 0, len(inputs))
	for _, input := range inputs {
		opened, exists := graph.ByUID[input.UID]
		if !exists || opened.Ref != input.Sealed {
			return nil, errors.New("apphost: transform input is not the exact visible revision")
		}
		found := false
		for _, payload := range opened.Revision.Payloads {
			if payload.Name == input.Payload {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("apphost: transform input payload is not visible")
		}
		selected = append(selected, engine.PluginInputSelection{Opened: opened, Payload: input.Payload})
	}
	return selected, nil
}

func transformRevisionPlans(ctx context.Context, graph engine.Graph, verifier artifact.EnrollmentVerifier) (map[artifact.UUID]*revisionPlan, error) {
	nodes := make(map[artifact.UUID]*revisionPlan, len(graph.ByUID))
	for uid, opened := range graph.ByUID {
		recipients, err := verifiedGrantRecipients(ctx, opened.Grant.Claims.Recipients, verifier)
		if err != nil {
			return nil, err
		}
		nodes[uid] = revisionPlanFromOpened(opened, recipients)
	}
	return nodes, nil
}

func validateTransformPlacements(nodes map[artifact.UUID]*revisionPlan, outputs []host.TransformOutput) error {
	for _, output := range outputs {
		if nodes[output.UID] != nil {
			return errors.New("apphost: transform output UID already exists")
		}
		parent := nodes[output.Parent]
		if parent == nil || parent.source == nil || parent.source.Ref != output.ExpectedParent {
			return errors.New("apphost: transform output parent is not the exact visible revision")
		}
		for _, edge := range parent.revision.Edges {
			if edge.ID == output.EdgeID || edge.Name == output.EdgeName {
				return errors.New("apphost: transform output edge collides with its parent")
			}
		}
	}
	return nil
}

func (executor *Executor) runPluginTransform(
	ctx context.Context,
	state *workspaceState,
	source artifact.ObjectSource,
	openedPolicy engine.OpenedRevision,
	inputs []engine.PluginInputSelection,
	action host.TransformAction,
) ([]engine.SealedRevision, error) {
	if len(action.Parameters) != 0 || executor.plugins == nil || executor.pluginHost == nil {
		return nil, errors.New("apphost: plugin transforms accept only pinned graph inputs")
	}
	verifiedPackage, err := executor.plugins.Resolve(ctx, action.Transform.Plugin)
	if err != nil {
		return nil, err
	}
	known, err := collectKnownRecipients(ctx, engine.Graph{ByUID: transformInputGraph(inputs)}, openedPolicy, state)
	if err != nil {
		return nil, err
	}
	verified := make([]artifact.VerifiedDevice, 0, len(known))
	for _, candidate := range known {
		verified = append(verified, candidate)
	}
	sortRecipients(verified)
	plans := make([]engine.PluginOutputPlan, 0, len(action.Outputs))
	for _, output := range action.Outputs {
		if len(output.Payloads) != 1 {
			return nil, errors.New("apphost: plugin output must have exactly one host-planned payload")
		}
		plans = append(plans, engine.PluginOutputPlan{
			Slot: output.Slot, UID: output.UID, Metadata: output.Metadata,
			PayloadName: output.Payloads[0].Name, PayloadMediaType: output.Payloads[0].MediaType,
		})
	}
	result, err := (engine.PluginTransformer{
		Host: executor.pluginHost, Source: source,
		Sealer:  engine.Sealer{Sink: state.objects, Issuer: state.device, Recipients: verified},
		TempDir: filepath.Join(state.stateDir, "plugin-tmp"),
	}).Transform(ctx, engine.PluginTransformRequest{
		Package: verifiedPackage, Inputs: inputs, Outputs: plans, PolicyRevision: openedPolicy.Ref.Revision,
	})
	if err != nil {
		return nil, err
	}
	if result.Package != action.Transform.Plugin {
		return nil, errors.New("apphost: plugin result package mismatch")
	}
	return result.Outputs, nil
}

func transformInputGraph(inputs []engine.PluginInputSelection) map[artifact.UUID]engine.OpenedRevision {
	result := make(map[artifact.UUID]engine.OpenedRevision, len(inputs))
	for _, input := range inputs {
		result[input.Opened.Revision.UID] = input.Opened
	}
	return result
}

func runBuiltinTransform(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	nodes map[artifact.UUID]*revisionPlan,
	policy artifact.SealedRef,
	action host.TransformAction,
) ([]engine.SealedRevision, error) {
	if action.Transform.Builtin.Group != "transforms.enbu.net" || action.Transform.Builtin.Version != "v1alpha1" {
		return nil, errors.New("apphost: unknown trusted built-in transform")
	}
	switch action.Transform.Builtin.Kind {
	case "OpaqueImport":
		return sealIndependentImports(ctx, execution, state, nodes, policy, action, "schemas.enbu.net/v1alpha1/Opaque", nil)
	case "DotEnvImport":
		return sealIndependentImports(ctx, execution, state, nodes, policy, action, "schemas.enbu.net/v1alpha1/SecretMap", canonicalDotEnv)
	case "CSVImport":
		return sealIndependentImports(ctx, execution, state, nodes, policy, action, "schemas.enbu.net/v1alpha1/Table", canonicalCSV)
	case "JSONImport":
		return sealIndependentImports(ctx, execution, state, nodes, policy, action, "schemas.enbu.net/v1alpha1/ValueTree", canonicalJSON)
	case "FileTreeImport":
		return sealFileTreeImport(ctx, execution, state, nodes, policy, action)
	default:
		return nil, errors.New("apphost: unknown trusted built-in transform")
	}
}

type canonicalizer func(io.Reader) ([]byte, error)

func sealIndependentImports(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	nodes map[artifact.UUID]*revisionPlan,
	policy artifact.SealedRef,
	action host.TransformAction,
	schemaName string,
	canonicalize canonicalizer,
) ([]engine.SealedRevision, error) {
	if len(action.Inputs) != 0 || len(action.Parameters) != len(action.Outputs) {
		return nil, errors.New("apphost: import transform requires one native parameter per output and no graph inputs")
	}
	parameters := make(map[string]host.InputHandle, len(action.Parameters))
	for _, parameter := range action.Parameters {
		parameters[parameter.Name] = parameter.Source
	}
	schemaRef, _ := artifact.ParseTypeRef(schemaName)
	result := make([]engine.SealedRevision, 0, len(action.Outputs))
	for _, output := range action.Outputs {
		handle, exists := parameters[output.Slot]
		if !exists || len(output.Payloads) != 1 {
			return nil, errors.New("apphost: import output slot or payload plan mismatch")
		}
		reader, err := execution.OpenInput(handle)
		if err != nil {
			return nil, err
		}
		payloadReader := io.Reader(reader)
		var canonical []byte
		if canonicalize != nil {
			canonical, err = canonicalize(reader)
			if err == nil {
				payloadReader = bytes.NewReader(canonical)
			}
		}
		if err != nil {
			_ = reader.Close()
			wipeSensitive(canonical)
			return nil, err
		}
		parentRecipients := append([]artifact.VerifiedDevice(nil), nodes[output.Parent].recipients...)
		sealed, sealErr := (engine.Sealer{Sink: state.objects, Issuer: state.device, Recipients: parentRecipients}).SealDraft(ctx, engine.Draft{
			Kind: artifact.KindResource, UID: output.UID, Schema: schemaRef, Metadata: output.Metadata,
			Payloads: []engine.PayloadSource{{Name: output.Payloads[0].Name, MediaType: output.Payloads[0].MediaType, Reader: payloadReader}},
		}, policy.Revision)
		closeErr := reader.Close()
		wipeSensitive(canonical)
		if sealErr != nil || closeErr != nil {
			return nil, errors.Join(sealErr, closeErr)
		}
		result = append(result, sealed)
	}
	return result, nil
}

func canonicalDotEnv(reader io.Reader) ([]byte, error) {
	data, err := readTransformBytes(reader)
	if err != nil {
		return nil, err
	}
	defer wipeSensitive(data)
	values, err := schema.DecodeSecretMap(data)
	if err != nil {
		return nil, err
	}
	return schema.EncodeSecretMap(values)
}

func canonicalCSV(reader io.Reader) ([]byte, error) {
	table, err := schema.DecodeTable(reader)
	if err != nil {
		return nil, err
	}
	return schema.EncodeTable(table)
}

func canonicalJSON(reader io.Reader) ([]byte, error) {
	data, err := readTransformBytes(reader)
	if err != nil {
		return nil, err
	}
	if err := schema.ValidateValueTree(data); err != nil {
		wipeSensitive(data)
		return nil, err
	}
	return data, nil
}

func readTransformBytes(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, schema.MaxOpaqueBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > schema.MaxOpaqueBytes {
		wipeSensitive(data)
		return nil, schema.ErrInvalidSchema
	}
	return data, nil
}

func sealFileTreeImport(
	ctx context.Context,
	execution host.Execution,
	state *workspaceState,
	nodes map[artifact.UUID]*revisionPlan,
	policy artifact.SealedRef,
	action host.TransformAction,
) ([]engine.SealedRevision, error) {
	if len(action.Inputs) != 0 || len(action.Outputs) != 1 || len(action.Parameters) == 0 {
		return nil, errors.New("apphost: FileTree import requires native files and one output")
	}
	readers := make([]io.ReadCloser, 0, len(action.Parameters))
	defer func() {
		for _, reader := range readers {
			_ = reader.Close()
		}
	}()
	inputs := make([]schema.FileTreeInput, 0, len(action.Parameters))
	for _, parameter := range action.Parameters {
		reader, err := execution.OpenInput(parameter.Source)
		if err != nil {
			return nil, err
		}
		readers = append(readers, reader)
		inputs = append(inputs, schema.FileTreeInput{Path: parameter.Name, MediaType: "application/octet-stream", Reader: reader})
	}
	imported, err := schema.NewFileTreeImport(ctx, inputs)
	if err != nil {
		return nil, err
	}
	streams := imported.Streams()
	output := action.Outputs[0]
	if len(streams) != len(output.Payloads) {
		return nil, errors.New("apphost: FileTree payload plan length mismatch")
	}
	draft := engine.Draft{Kind: artifact.KindResource, UID: output.UID, Metadata: output.Metadata}
	draft.Schema, _ = artifact.ParseTypeRef(schema.SchemaFileTree)
	for index, stream := range streams {
		planned := output.Payloads[index]
		if planned.Name != stream.Name || planned.MediaType != stream.MediaType {
			return nil, errors.New("apphost: FileTree payload plan mismatch")
		}
		draft.Payloads = append(draft.Payloads, engine.PayloadSource{Name: stream.Name, MediaType: stream.MediaType, Reader: stream.Reader})
	}
	sealed, err := (engine.Sealer{
		Sink: state.objects, Issuer: state.device, Recipients: append([]artifact.VerifiedDevice(nil), nodes[output.Parent].recipients...),
	}).SealDraft(ctx, draft, policy.Revision)
	if err != nil {
		return nil, err
	}
	return []engine.SealedRevision{sealed}, nil
}

func attachTransformOutputs(nodes map[artifact.UUID]*revisionPlan, plans []host.TransformOutput, outputs []engine.SealedRevision) error {
	if len(plans) != len(outputs) {
		return errors.New("apphost: transform output count mismatch")
	}
	sealedByUID := make(map[artifact.UUID]engine.SealedRevision, len(outputs))
	for _, sealed := range outputs {
		sealedByUID[sealed.Revision.UID] = sealed
	}
	for _, output := range plans {
		sealed, exists := sealedByUID[output.UID]
		if !exists || len(sealed.Revision.Payloads) != len(output.Payloads) {
			return errors.New("apphost: transform output identity or payload count mismatch")
		}
		for index, payload := range sealed.Revision.Payloads {
			if payload.Name != output.Payloads[index].Name || payload.MediaType != output.Payloads[index].MediaType {
				return errors.New("apphost: transform output payload mismatch")
			}
		}
		parent := nodes[output.Parent]
		ref := sealed.Ref
		parent.revision.Edges = append(parent.revision.Edges, artifact.Edge{
			ID: output.EdgeID, Name: output.EdgeName, Relation: output.Relation,
			Strength: artifact.EdgePinned, Target: output.UID, Pinned: &ref,
		})
		parent.forceSeal = true
		nodes[output.UID] = &revisionPlan{
			revision: sealed.Revision, done: true, result: sealed.Ref, closure: sealed.Closure,
		}
	}
	return nil
}

func transformProvenance(action host.TransformAction, nodes map[artifact.UUID]*revisionPlan) ([]commitmodel.MutationProvenance, []host.ResourceChange, error) {
	actionType, _ := artifact.ParseTypeRef("operations.enbu.net/v1alpha1/Transform")
	inputs := make([]commitmodel.PinnedInput, 0, len(action.Inputs))
	for _, input := range action.Inputs {
		inputs = append(inputs, commitmodel.PinnedInput{Role: input.Role, UID: input.UID, Sealed: input.Sealed})
	}
	records := make([]commitmodel.MutationProvenance, 0, len(action.Outputs))
	changes := make([]host.ResourceChange, 0, len(action.Outputs)*2)
	changedParents := make(map[artifact.UUID]struct{})
	for _, output := range action.Outputs {
		id, err := newUUID()
		if err != nil {
			return nil, nil, err
		}
		after := nodes[output.UID].result
		records = append(records, commitmodel.MutationProvenance{
			ID: id, Action: actionType, Target: output.UID, After: &after,
			Inputs: append([]commitmodel.PinnedInput(nil), inputs...), Plugin: action.Transform.Plugin,
		})
		changes = append(changes, host.ResourceChange{UID: output.UID, Kind: host.ResourceCreated, After: after.Revision})
		changedParents[output.Parent] = struct{}{}
	}
	parents := make([]artifact.UUID, 0, len(changedParents))
	for parent := range changedParents {
		parents = append(parents, parent)
	}
	sort.Slice(parents, func(i, j int) bool { return parents[i] < parents[j] })
	for _, parent := range parents {
		plan := nodes[parent]
		changes = append(changes, host.ResourceChange{
			UID: parent, Kind: host.ResourceUpdated, Before: plan.source.Ref.Revision, After: plan.result.Revision,
		})
	}
	return records, changes, nil
}

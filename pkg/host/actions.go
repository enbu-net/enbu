package host

import (
	"fmt"
	"mime"
	"strings"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	MaxActionChanges       = 10_000
	MaxTransformInputs     = 1_024
	MaxTransformParameters = 1_024
	MaxTransformOutputs    = 1_024
	MaxAccessTargets       = 10_000
	MaxAccessCandidates    = 10_000
	MaxMergeHeads          = 64
	MaxConflictResolutions = 10_000
)

// ActionKind is a fixed host-owned operation category. Schema and format
// extensibility belongs to TypeRef and TransformRef, not to new client APIs.
type ActionKind string

const (
	ActionInitialize   ActionKind = "initialize"
	ActionApply        ActionKind = "apply"
	ActionTransform    ActionKind = "transform"
	ActionMaterialize  ActionKind = "materialize"
	ActionChangeAccess ActionKind = "change_access"
	ActionChangePolicy ActionKind = "change_policy"
	ActionMerge        ActionKind = "merge"
	ActionRestore      ActionKind = "restore"
)

// Action is deliberately closed. Only host-owned action types can cross the
// application boundary; callers cannot register executable closures.
type Action interface {
	Kind() ActionKind
	hostAction()
	validate() error
	handles() actionHandles
}

type actionHandles struct {
	inputs  []InputHandle
	outputs []OutputHandle
}

type StagedPayload struct {
	Name      string
	MediaType string
	Source    InputHandle
}

// DraftResource contains graph metadata and opaque stream capabilities only.
// Payload bytes and local paths are intentionally impossible to put here.
type DraftResource struct {
	Kind     artifact.Kind
	UID      artifact.UUID
	Schema   artifact.TypeRef
	Metadata artifact.Metadata
	Payloads []StagedPayload
	Edges    []artifact.Edge
}

type InitializeAction struct {
	OwnerEnrollment digest.Digest
	Root            DraftResource
	Policy          DraftResource
}

func (InitializeAction) Kind() ActionKind { return ActionInitialize }
func (InitializeAction) hostAction()      {}
func (action InitializeAction) validate() error {
	if err := validateSHA256(action.OwnerEnrollment); err != nil {
		return fmt.Errorf("%w: owner enrollment: %v", ErrInvalidAction, err)
	}
	if err := validateDraft(action.Root); err != nil {
		return fmt.Errorf("%w: root: %v", ErrInvalidAction, err)
	}
	if action.Root.Kind != artifact.KindCollection {
		return fmt.Errorf("%w: initialization root must be a Collection", ErrInvalidAction)
	}
	if err := validateDraft(action.Policy); err != nil {
		return fmt.Errorf("%w: policy: %v", ErrInvalidAction, err)
	}
	return nil
}
func (action InitializeAction) handles() actionHandles {
	return actionHandles{inputs: append(draftHandles(action.Root), draftHandles(action.Policy)...)}
}

type ApplyAction struct {
	BaseCommit digest.Digest
	Changes    []GraphChange
}

func (ApplyAction) Kind() ActionKind { return ActionApply }
func (ApplyAction) hostAction()      {}
func (action ApplyAction) validate() error {
	if err := validateBase(action.BaseCommit); err != nil {
		return err
	}
	if len(action.Changes) == 0 || len(action.Changes) > MaxActionChanges {
		return fmt.Errorf("%w: apply requires 1-%d changes", ErrInvalidAction, MaxActionChanges)
	}
	for index, change := range action.Changes {
		if err := change.validate(); err != nil {
			return fmt.Errorf("%w: changes[%d]: %v", ErrInvalidAction, index, err)
		}
	}
	return nil
}
func (action ApplyAction) handles() actionHandles {
	var result actionHandles
	for _, change := range action.Changes {
		result.inputs = append(result.inputs, change.handles()...)
	}
	return result
}

// GraphChange is an exactly-one tagged union. Expected revisions make every
// replacement, deletion, and edge mutation optimistic rather than last-write-
// wins.
type GraphChange struct {
	Create     *CreateResource
	Replace    *ReplaceResource
	Delete     *DeleteResource
	PutEdge    *PutEdge
	DeleteEdge *DeleteEdge
}

type CreateResource struct{ Draft DraftResource }
type ReplaceResource struct {
	Expected artifact.SealedRef
	Draft    DraftResource
}
type DeleteResource struct {
	UID      artifact.UUID
	Expected artifact.SealedRef
}
type PutEdge struct {
	Parent         artifact.UUID
	ExpectedParent artifact.SealedRef
	Edge           artifact.Edge
}
type DeleteEdge struct {
	Parent         artifact.UUID
	ExpectedParent artifact.SealedRef
	EdgeID         artifact.UUID
}

func (change GraphChange) validate() error {
	count := 0
	for _, present := range []bool{change.Create != nil, change.Replace != nil, change.Delete != nil, change.PutEdge != nil, change.DeleteEdge != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("graph change must select exactly one variant")
	}
	switch {
	case change.Create != nil:
		return validateDraft(change.Create.Draft)
	case change.Replace != nil:
		if err := change.Replace.Expected.Validate(); err != nil {
			return fmt.Errorf("expected revision: %v", err)
		}
		return validateDraft(change.Replace.Draft)
	case change.Delete != nil:
		if err := change.Delete.UID.Validate(); err != nil {
			return fmt.Errorf("delete UID: %v", err)
		}
		return change.Delete.Expected.Validate()
	case change.PutEdge != nil:
		if err := change.PutEdge.Parent.Validate(); err != nil {
			return fmt.Errorf("parent UID: %v", err)
		}
		if err := change.PutEdge.ExpectedParent.Validate(); err != nil {
			return fmt.Errorf("expected parent: %v", err)
		}
		return change.PutEdge.Edge.Validate()
	default:
		if err := change.DeleteEdge.Parent.Validate(); err != nil {
			return fmt.Errorf("parent UID: %v", err)
		}
		if err := change.DeleteEdge.ExpectedParent.Validate(); err != nil {
			return fmt.Errorf("expected parent: %v", err)
		}
		return change.DeleteEdge.EdgeID.Validate()
	}
}

func (change GraphChange) handles() []InputHandle {
	switch {
	case change.Create != nil:
		return draftHandles(change.Create.Draft)
	case change.Replace != nil:
		return draftHandles(change.Replace.Draft)
	default:
		return nil
	}
}

type TransformRef struct {
	Builtin artifact.TypeRef
	Plugin  digest.Digest
}

func (ref TransformRef) validate() error {
	hasBuiltin := ref.Builtin != (artifact.TypeRef{})
	hasPlugin := ref.Plugin != ""
	if hasBuiltin == hasPlugin {
		return fmt.Errorf("transform must select exactly one built-in or plugin")
	}
	if hasBuiltin {
		return ref.Builtin.Validate()
	}
	return validateSHA256(ref.Plugin)
}

type PinnedInput struct {
	Role    artifact.TypeRef
	UID     artifact.UUID
	Sealed  artifact.SealedRef
	Payload string
}

func (input PinnedInput) validate() error {
	if err := input.Role.Validate(); err != nil {
		return err
	}
	if err := input.UID.Validate(); err != nil {
		return err
	}
	if err := validateName(input.Payload); err != nil {
		return fmt.Errorf("payload: %v", err)
	}
	return input.Sealed.Validate()
}

type TransformParameter struct {
	Name   string
	Source InputHandle
}

// TransformOutput is the host-owned graph and storage plan for one transform
// result. A plugin may select only an authorized extension schema for Slot;
// it cannot choose graph identity, metadata, payload semantics, or placement.
type TransformOutput struct {
	Slot           string
	UID            artifact.UUID
	Metadata       artifact.Metadata
	Parent         artifact.UUID
	ExpectedParent artifact.SealedRef
	EdgeID         artifact.UUID
	EdgeName       string
	Relation       artifact.TypeRef
	Payloads       []TransformPayload
}

type TransformPayload struct {
	Name      string
	MediaType string
}

type TransformAction struct {
	BaseCommit digest.Digest
	Transform  TransformRef
	Inputs     []PinnedInput
	Parameters []TransformParameter
	Outputs    []TransformOutput
}

func (TransformAction) Kind() ActionKind { return ActionTransform }
func (TransformAction) hostAction()      {}
func (action TransformAction) validate() error {
	if err := validateBase(action.BaseCommit); err != nil {
		return err
	}
	if err := action.Transform.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAction, err)
	}
	if len(action.Inputs) > MaxTransformInputs || (action.Transform.Plugin != "" && len(action.Inputs) == 0) {
		return fmt.Errorf("%w: transform input bounds", ErrInvalidAction)
	}
	type inputKey struct {
		role artifact.TypeRef
		uid  artifact.UUID
	}
	seenInputs := make(map[inputKey]struct{}, len(action.Inputs))
	for index, input := range action.Inputs {
		if err := input.validate(); err != nil {
			return fmt.Errorf("%w: inputs[%d]: %v", ErrInvalidAction, index, err)
		}
		key := inputKey{role: input.Role, uid: input.UID}
		if _, exists := seenInputs[key]; exists {
			return fmt.Errorf("%w: duplicate transform input role and UID", ErrInvalidAction)
		}
		seenInputs[key] = struct{}{}
	}
	if len(action.Parameters) > MaxTransformParameters {
		return fmt.Errorf("%w: too many transform parameters", ErrInvalidAction)
	}
	seen := make(map[string]struct{}, len(action.Parameters))
	for index, parameter := range action.Parameters {
		if err := validateName(parameter.Name); err != nil {
			return fmt.Errorf("%w: parameters[%d]: %v", ErrInvalidAction, index, err)
		}
		if err := parameter.Source.validate(); err != nil {
			return fmt.Errorf("%w: parameters[%d] handle: %v", ErrInvalidAction, index, err)
		}
		if _, exists := seen[parameter.Name]; exists {
			return fmt.Errorf("%w: duplicate transform parameter %q", ErrInvalidAction, parameter.Name)
		}
		seen[parameter.Name] = struct{}{}
	}
	if len(action.Outputs) == 0 || len(action.Outputs) > MaxTransformOutputs {
		return fmt.Errorf("%w: transform requires 1-%d output plans", ErrInvalidAction, MaxTransformOutputs)
	}
	seenSlots := make(map[string]struct{}, len(action.Outputs))
	seenUIDs := make(map[artifact.UUID]struct{}, len(action.Outputs))
	seenEdges := make(map[artifact.UUID]struct{}, len(action.Outputs))
	for index, output := range action.Outputs {
		if err := validateTransformOutput(output); err != nil {
			return fmt.Errorf("%w: outputs[%d]: %v", ErrInvalidAction, index, err)
		}
		if _, exists := seenSlots[output.Slot]; exists {
			return fmt.Errorf("%w: duplicate transform output slot", ErrInvalidAction)
		}
		seenSlots[output.Slot] = struct{}{}
		if _, exists := seenUIDs[output.UID]; exists {
			return fmt.Errorf("%w: duplicate transform output UID", ErrInvalidAction)
		}
		seenUIDs[output.UID] = struct{}{}
		if _, exists := seenEdges[output.EdgeID]; exists {
			return fmt.Errorf("%w: duplicate transform output edge", ErrInvalidAction)
		}
		seenEdges[output.EdgeID] = struct{}{}
	}
	return nil
}
func (action TransformAction) handles() actionHandles {
	result := actionHandles{inputs: make([]InputHandle, 0, len(action.Parameters))}
	for _, parameter := range action.Parameters {
		result.inputs = append(result.inputs, parameter.Source)
	}
	return result
}

func validateTransformOutput(output TransformOutput) error {
	if err := validateName(output.Slot); err != nil {
		return fmt.Errorf("slot: %v", err)
	}
	if err := output.UID.Validate(); err != nil {
		return fmt.Errorf("UID: %v", err)
	}
	if err := output.Metadata.Validate(); err != nil {
		return fmt.Errorf("metadata: %v", err)
	}
	if err := output.Parent.Validate(); err != nil || output.Parent == output.UID {
		return fmt.Errorf("parent: invalid or self-referential")
	}
	if err := output.ExpectedParent.Validate(); err != nil {
		return fmt.Errorf("expected parent: %v", err)
	}
	if err := output.EdgeID.Validate(); err != nil {
		return fmt.Errorf("edge ID: %v", err)
	}
	if err := validateName(output.EdgeName); err != nil {
		return fmt.Errorf("edge name: %v", err)
	}
	if err := output.Relation.Validate(); err != nil {
		return fmt.Errorf("relation: %v", err)
	}
	if len(output.Payloads) == 0 || len(output.Payloads) > artifact.MaxPayloads {
		return fmt.Errorf("payload plan bounds")
	}
	seenPayloads := make(map[string]struct{}, len(output.Payloads))
	for index, payload := range output.Payloads {
		if err := validateName(payload.Name); err != nil {
			return fmt.Errorf("payloads[%d] name: %v", index, err)
		}
		if _, _, err := mime.ParseMediaType(payload.MediaType); err != nil {
			return fmt.Errorf("payloads[%d] media type: %v", index, err)
		}
		if _, exists := seenPayloads[payload.Name]; exists {
			return fmt.Errorf("duplicate payload plan")
		}
		seenPayloads[payload.Name] = struct{}{}
	}
	return nil
}

type MaterializeAction struct {
	AtCommit    digest.Digest
	Target      artifact.UUID
	Format      artifact.TypeRef
	Payload     string
	Destination OutputHandle
}

func (MaterializeAction) Kind() ActionKind { return ActionMaterialize }
func (MaterializeAction) hostAction()      {}
func (action MaterializeAction) validate() error {
	if err := validateSHA256(action.AtCommit); err != nil {
		return fmt.Errorf("%w: commit: %v", ErrInvalidAction, err)
	}
	if err := action.Target.Validate(); err != nil {
		return fmt.Errorf("%w: target: %v", ErrInvalidAction, err)
	}
	if err := action.Format.Validate(); err != nil {
		return fmt.Errorf("%w: format: %v", ErrInvalidAction, err)
	}
	if action.Payload != "" {
		if err := validateName(action.Payload); err != nil {
			return fmt.Errorf("%w: payload: %v", ErrInvalidAction, err)
		}
	}
	if err := action.Destination.validate(); err != nil {
		return fmt.Errorf("%w: destination: %v", ErrInvalidAction, err)
	}
	return nil
}
func (action MaterializeAction) handles() actionHandles {
	return actionHandles{outputs: []OutputHandle{action.Destination}}
}

type AccessMode string

const (
	AccessGrant  AccessMode = "grant"
	AccessRevoke AccessMode = "revoke"
)

type EnrollmentRef struct{ Digest digest.Digest }

type ChangeAccessAction struct {
	BaseCommit digest.Digest
	Targets    []artifact.UUID
	Mode       AccessMode
	Candidates []EnrollmentRef
}

type ChangePolicyAction struct {
	BaseCommit digest.Digest
	Expected   artifact.SealedRef
	Policy     DraftResource
}

func (ChangePolicyAction) Kind() ActionKind { return ActionChangePolicy }
func (ChangePolicyAction) hostAction()      {}
func (action ChangePolicyAction) validate() error {
	if err := validateBase(action.BaseCommit); err != nil {
		return err
	}
	if err := action.Expected.Validate(); err != nil {
		return fmt.Errorf("%w: expected policy: %v", ErrInvalidAction, err)
	}
	if err := validateDraft(action.Policy); err != nil {
		return fmt.Errorf("%w: policy: %v", ErrInvalidAction, err)
	}
	if action.Policy.Kind != artifact.KindResource {
		return fmt.Errorf("%w: policy must be a Resource", ErrInvalidAction)
	}
	return nil
}
func (action ChangePolicyAction) handles() actionHandles {
	return actionHandles{inputs: draftHandles(action.Policy)}
}

func (ChangeAccessAction) Kind() ActionKind { return ActionChangeAccess }
func (ChangeAccessAction) hostAction()      {}
func (action ChangeAccessAction) validate() error {
	if err := validateBase(action.BaseCommit); err != nil {
		return err
	}
	if action.Mode != AccessGrant && action.Mode != AccessRevoke {
		return fmt.Errorf("%w: invalid access mode", ErrInvalidAction)
	}
	if len(action.Targets) == 0 || len(action.Targets) > MaxAccessTargets || len(action.Candidates) == 0 || len(action.Candidates) > MaxAccessCandidates {
		return fmt.Errorf("%w: access target/candidate bounds", ErrInvalidAction)
	}
	seenTargets := make(map[artifact.UUID]struct{}, len(action.Targets))
	for _, target := range action.Targets {
		if err := target.Validate(); err != nil {
			return fmt.Errorf("%w: target: %v", ErrInvalidAction, err)
		}
		if _, exists := seenTargets[target]; exists {
			return fmt.Errorf("%w: duplicate access target", ErrInvalidAction)
		}
		seenTargets[target] = struct{}{}
	}
	seenCandidates := make(map[digest.Digest]struct{}, len(action.Candidates))
	for _, candidate := range action.Candidates {
		if err := validateSHA256(candidate.Digest); err != nil {
			return fmt.Errorf("%w: candidate enrollment: %v", ErrInvalidAction, err)
		}
		if _, exists := seenCandidates[candidate.Digest]; exists {
			return fmt.Errorf("%w: duplicate access candidate", ErrInvalidAction)
		}
		seenCandidates[candidate.Digest] = struct{}{}
	}
	return nil
}
func (ChangeAccessAction) handles() actionHandles { return actionHandles{} }

type ConflictResolution struct {
	ConflictID   artifact.UUID
	SelectCommit digest.Digest
}

type MergeAction struct {
	Heads       []digest.Digest
	Resolutions []ConflictResolution
}

func (MergeAction) Kind() ActionKind { return ActionMerge }
func (MergeAction) hostAction()      {}
func (action MergeAction) validate() error {
	if len(action.Heads) < 2 || len(action.Heads) > MaxMergeHeads {
		return fmt.Errorf("%w: merge requires 2-%d heads", ErrInvalidAction, MaxMergeHeads)
	}
	seenHeads := make(map[digest.Digest]struct{}, len(action.Heads))
	for _, head := range action.Heads {
		if err := validateSHA256(head); err != nil {
			return fmt.Errorf("%w: merge head: %v", ErrInvalidAction, err)
		}
		if _, exists := seenHeads[head]; exists {
			return fmt.Errorf("%w: duplicate merge head", ErrInvalidAction)
		}
		seenHeads[head] = struct{}{}
	}
	if len(action.Resolutions) > MaxConflictResolutions {
		return fmt.Errorf("%w: too many conflict resolutions", ErrInvalidAction)
	}
	seenConflicts := make(map[artifact.UUID]struct{}, len(action.Resolutions))
	for _, resolution := range action.Resolutions {
		if err := resolution.ConflictID.Validate(); err != nil {
			return fmt.Errorf("%w: conflict ID: %v", ErrInvalidAction, err)
		}
		if _, exists := seenHeads[resolution.SelectCommit]; !exists {
			return fmt.Errorf("%w: conflict resolution must select a merge head", ErrInvalidAction)
		}
		if _, exists := seenConflicts[resolution.ConflictID]; exists {
			return fmt.Errorf("%w: duplicate conflict resolution", ErrInvalidAction)
		}
		seenConflicts[resolution.ConflictID] = struct{}{}
	}
	return nil
}
func (MergeAction) handles() actionHandles { return actionHandles{} }

type RestoreAction struct {
	BaseCommit   digest.Digest
	SourceCommit digest.Digest
}

func (RestoreAction) Kind() ActionKind { return ActionRestore }
func (RestoreAction) hostAction()      {}
func (action RestoreAction) validate() error {
	if err := validateBase(action.BaseCommit); err != nil {
		return err
	}
	if err := validateSHA256(action.SourceCommit); err != nil {
		return fmt.Errorf("%w: source commit: %v", ErrInvalidAction, err)
	}
	if action.BaseCommit == action.SourceCommit {
		return fmt.Errorf("%w: restore source equals base", ErrInvalidAction)
	}
	return nil
}
func (RestoreAction) handles() actionHandles { return actionHandles{} }

func validateBase(value digest.Digest) error {
	if err := validateSHA256(value); err != nil {
		return fmt.Errorf("%w: base commit: %v", ErrInvalidAction, err)
	}
	return nil
}

func validateSHA256(value digest.Digest) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.Algorithm() != digest.SHA256 {
		return fmt.Errorf("digest algorithm must be sha256")
	}
	return nil
}

func validateName(value string) error {
	if value == "" || len(value) > 253 || strings.ContainsRune(value, 0) {
		return fmt.Errorf("invalid name")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("invalid name")
		}
	}
	return nil
}

func validateDraft(draft DraftResource) error {
	if draft.Kind != artifact.KindResource && draft.Kind != artifact.KindCollection {
		return fmt.Errorf("invalid resource kind")
	}
	if err := draft.UID.Validate(); err != nil {
		return err
	}
	if err := draft.Schema.Validate(); err != nil {
		return err
	}
	if err := draft.Metadata.Validate(); err != nil {
		return err
	}
	if len(draft.Payloads) > artifact.MaxPayloads || len(draft.Edges) > artifact.MaxEdges {
		return fmt.Errorf("draft exceeds graph bounds")
	}
	if draft.Kind == artifact.KindCollection && len(draft.Payloads) != 0 {
		return fmt.Errorf("collection must not have payloads")
	}
	seenPayloads := make(map[string]struct{}, len(draft.Payloads))
	for _, payload := range draft.Payloads {
		if err := validateName(payload.Name); err != nil {
			return fmt.Errorf("payload name: %v", err)
		}
		if _, _, err := mime.ParseMediaType(payload.MediaType); err != nil {
			return fmt.Errorf("payload media type: %v", err)
		}
		if err := payload.Source.validate(); err != nil {
			return fmt.Errorf("payload source: %v", err)
		}
		if _, exists := seenPayloads[payload.Name]; exists {
			return fmt.Errorf("duplicate payload name")
		}
		seenPayloads[payload.Name] = struct{}{}
	}
	seenEdges := make(map[artifact.UUID]struct{}, len(draft.Edges))
	for _, edge := range draft.Edges {
		if err := edge.Validate(); err != nil {
			return err
		}
		if _, exists := seenEdges[edge.ID]; exists {
			return fmt.Errorf("duplicate edge ID")
		}
		seenEdges[edge.ID] = struct{}{}
	}
	return nil
}

func draftHandles(draft DraftResource) []InputHandle {
	result := make([]InputHandle, 0, len(draft.Payloads))
	for _, payload := range draft.Payloads {
		result = append(result, payload.Source)
	}
	return result
}

func cloneAction(action Action) (Action, error) {
	if action == nil {
		return nil, ErrInvalidAction
	}
	switch value := action.(type) {
	case InitializeAction:
		return cloneInitialize(value), nil
	case *InitializeAction:
		if value == nil {
			return nil, ErrInvalidAction
		}
		return cloneInitialize(*value), nil
	case ApplyAction:
		return cloneApply(value), nil
	case *ApplyAction:
		if value == nil {
			return nil, ErrInvalidAction
		}
		return cloneApply(*value), nil
	case TransformAction:
		return cloneTransform(value), nil
	case *TransformAction:
		if value == nil {
			return nil, ErrInvalidAction
		}
		return cloneTransform(*value), nil
	case MaterializeAction:
		return value, nil
	case *MaterializeAction:
		if value == nil {
			return nil, ErrInvalidAction
		}
		return *value, nil
	case ChangeAccessAction:
		return cloneChangeAccess(value), nil
	case *ChangeAccessAction:
		if value == nil {
			return nil, ErrInvalidAction
		}
		return cloneChangeAccess(*value), nil
	case ChangePolicyAction:
		value.Policy = cloneDraft(value.Policy)
		return value, nil
	case *ChangePolicyAction:
		if value == nil {
			return nil, ErrInvalidAction
		}
		clone := *value
		clone.Policy = cloneDraft(clone.Policy)
		return clone, nil
	case MergeAction:
		return cloneMerge(value), nil
	case *MergeAction:
		if value == nil {
			return nil, ErrInvalidAction
		}
		return cloneMerge(*value), nil
	case RestoreAction:
		return value, nil
	case *RestoreAction:
		if value == nil {
			return nil, ErrInvalidAction
		}
		return *value, nil
	default:
		return nil, ErrInvalidAction
	}
}

func cloneInitialize(value InitializeAction) InitializeAction {
	value.Root = cloneDraft(value.Root)
	value.Policy = cloneDraft(value.Policy)
	return value
}

func cloneApply(value ApplyAction) ApplyAction {
	value.Changes = append([]GraphChange(nil), value.Changes...)
	for index := range value.Changes {
		value.Changes[index] = cloneGraphChange(value.Changes[index])
	}
	return value
}

func cloneTransform(value TransformAction) TransformAction {
	value.Inputs = append([]PinnedInput(nil), value.Inputs...)
	value.Parameters = append([]TransformParameter(nil), value.Parameters...)
	value.Outputs = append([]TransformOutput(nil), value.Outputs...)
	for index := range value.Outputs {
		value.Outputs[index].Metadata.Labels = cloneStrings(value.Outputs[index].Metadata.Labels)
		value.Outputs[index].Metadata.Annotations = cloneStrings(value.Outputs[index].Metadata.Annotations)
		value.Outputs[index].Payloads = append([]TransformPayload(nil), value.Outputs[index].Payloads...)
	}
	return value
}

func cloneChangeAccess(value ChangeAccessAction) ChangeAccessAction {
	value.Targets = append([]artifact.UUID(nil), value.Targets...)
	value.Candidates = append([]EnrollmentRef(nil), value.Candidates...)
	return value
}

func cloneMerge(value MergeAction) MergeAction {
	value.Heads = append([]digest.Digest(nil), value.Heads...)
	value.Resolutions = append([]ConflictResolution(nil), value.Resolutions...)
	return value
}

func cloneDraft(value DraftResource) DraftResource {
	value.Metadata.Labels = cloneStrings(value.Metadata.Labels)
	value.Metadata.Annotations = cloneStrings(value.Metadata.Annotations)
	value.Payloads = append([]StagedPayload(nil), value.Payloads...)
	value.Edges = append([]artifact.Edge(nil), value.Edges...)
	for index := range value.Edges {
		if value.Edges[index].Pinned != nil {
			pinned := *value.Edges[index].Pinned
			value.Edges[index].Pinned = &pinned
		}
	}
	return value
}

func cloneGraphChange(value GraphChange) GraphChange {
	if value.Create != nil {
		cloned := *value.Create
		cloned.Draft = cloneDraft(cloned.Draft)
		value.Create = &cloned
	}
	if value.Replace != nil {
		cloned := *value.Replace
		cloned.Draft = cloneDraft(cloned.Draft)
		value.Replace = &cloned
	}
	if value.Delete != nil {
		cloned := *value.Delete
		value.Delete = &cloned
	}
	if value.PutEdge != nil {
		cloned := *value.PutEdge
		if cloned.Edge.Pinned != nil {
			pinned := *cloned.Edge.Pinned
			cloned.Edge.Pinned = &pinned
		}
		value.PutEdge = &cloned
	}
	if value.DeleteEdge != nil {
		cloned := *value.DeleteEdge
		value.DeleteEdge = &cloned
	}
	return value
}

func cloneStrings(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string]string, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

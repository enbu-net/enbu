package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/cas"
	"github.com/enbu-net/enbu/pkg/platform"
	"github.com/enbu-net/enbu/pkg/plugin"
	"github.com/opencontainers/go-digest"
)

var (
	ErrInvalidPluginTransform     = errors.New("engine: invalid plugin transform")
	ErrEmptyRecipientIntersection = errors.New("engine: plugin input recipient intersection is empty")
)

// PluginInputSelection names one already authenticated payload. Slice order is
// the dense, execution-scoped handle order exposed to the WASM module.
type PluginInputSelection struct {
	Opened  OpenedRevision
	Payload string
}

// PluginOutputPlan is host authority for the graph identity and storage shape
// of one plugin output slot. The plugin supplies only its extension TypeRef and
// bytes; it cannot choose UID, edges, metadata, payload semantics, or access.
type PluginOutputPlan struct {
	Slot             string
	UID              artifact.UUID
	Metadata         artifact.Metadata
	PayloadName      string
	PayloadMediaType string
	Edges            []artifact.Edge
}

type PluginTransformRequest struct {
	Package        plugin.VerifiedPackage
	Inputs         []PluginInputSelection
	Outputs        []PluginOutputPlan
	PolicyRevision digest.Digest
}

type PluginTransformResult struct {
	Package digest.Digest
	Outputs []SealedRevision
}

// PluginTransformer is the trusted adapter between authenticated graph state
// and the capability-restricted WASM runtime. TempDir must be a host-selected
// absolute private directory, never a repository-controlled path.
type PluginTransformer struct {
	Host    *plugin.Host
	Source  artifact.ObjectSource
	Sealer  Sealer
	TempDir string
}

func (transformer PluginTransformer) Transform(
	ctx context.Context,
	request PluginTransformRequest,
) (result PluginTransformResult, returnedErr error) {
	if ctx == nil {
		return PluginTransformResult{}, fmt.Errorf("%w: nil context", ErrInvalidPluginTransform)
	}
	if err := ctx.Err(); err != nil {
		return PluginTransformResult{}, err
	}
	if transformer.Host == nil || transformer.Source == nil || transformer.Sealer.Sink == nil ||
		transformer.Sealer.Issuer == nil || transformer.TempDir == "" || !filepath.IsAbs(transformer.TempDir) {
		return PluginTransformResult{}, fmt.Errorf("%w: incomplete transformer", ErrInvalidPluginTransform)
	}
	if err := validatePluginRequest(request); err != nil {
		return PluginTransformResult{}, err
	}

	recipients, err := intersectPluginRecipients(request.Inputs, transformer.Sealer.Recipients)
	if err != nil {
		return PluginTransformResult{}, err
	}
	storage, err := newPluginExecutionStorage(transformer.TempDir)
	if err != nil {
		return PluginTransformResult{}, err
	}
	defer func() {
		if cleanupErr := storage.Close(); cleanupErr != nil {
			returnedErr = errors.Join(returnedErr, cleanupErr)
		}
	}()

	inputs := make([]plugin.Input, 0, len(request.Inputs))
	openedFiles := make([]*os.File, 0, len(request.Inputs))
	for index, selection := range request.Inputs {
		input, file, spoolErr := spoolPluginInput(ctx, transformer.Source, storage.inputDir, selection)
		if spoolErr != nil {
			_ = closePluginInputs(openedFiles)
			return PluginTransformResult{}, fmt.Errorf("prepare plugin input %d: %w", index, spoolErr)
		}
		inputs = append(inputs, input)
		openedFiles = append(openedFiles, file)
	}

	drafts, executeErr := transformer.Host.Execute(ctx, request.Package, inputs, storage.store)
	closeErr := closePluginInputs(openedFiles)
	if executeErr != nil || closeErr != nil {
		return PluginTransformResult{}, errors.Join(executeErr, closeErr)
	}
	if err := ctx.Err(); err != nil {
		return PluginTransformResult{}, err
	}

	plans := make(map[string]PluginOutputPlan, len(request.Outputs))
	for _, plan := range request.Outputs {
		plans[plan.Slot] = plan
	}
	if len(drafts) != len(plans) {
		return PluginTransformResult{}, fmt.Errorf("%w: plugin produced %d outputs, host planned %d", ErrInvalidPluginTransform, len(drafts), len(plans))
	}

	outputSealer := transformer.Sealer
	outputSealer.Recipients = recipients
	sealedOutputs := make([]SealedRevision, 0, len(drafts))
	for index, staged := range drafts {
		if err := ctx.Err(); err != nil {
			return PluginTransformResult{}, err
		}
		if err := staged.Type.ValidateExtension(); err != nil {
			return PluginTransformResult{}, fmt.Errorf("%w: output %d type: %w", ErrInvalidPluginTransform, index, err)
		}
		if err := staged.Metadata.ValidateExtension(); err != nil || len(staged.Metadata.Labels) != 0 || len(staged.Metadata.Annotations) != 0 {
			return PluginTransformResult{}, fmt.Errorf("%w: output %d metadata is not an inert slot", ErrInvalidPluginTransform, index)
		}
		plan, ok := plans[staged.Metadata.Name]
		if !ok {
			return PluginTransformResult{}, fmt.Errorf("%w: plugin produced unplanned output slot %q", ErrInvalidPluginTransform, staged.Metadata.Name)
		}
		delete(plans, staged.Metadata.Name)

		reader, err := openPluginDraft(ctx, storage.store, staged.Object)
		if err != nil {
			return PluginTransformResult{}, fmt.Errorf("open plugin output %q: %w", staged.Metadata.Name, err)
		}
		sealed, sealErr := outputSealer.SealDraft(ctx, Draft{
			Kind:     artifact.KindResource,
			UID:      plan.UID,
			Schema:   staged.Type,
			Metadata: cloneMetadata(plan.Metadata),
			Payloads: []PayloadSource{{
				Name:      plan.PayloadName,
				MediaType: plan.PayloadMediaType,
				Reader:    reader,
			}},
			Edges: cloneEdges(plan.Edges),
		}, request.PolicyRevision)
		readerCloseErr := reader.Close()
		if sealErr != nil || readerCloseErr != nil {
			return PluginTransformResult{}, errors.Join(sealErr, readerCloseErr)
		}
		sealedOutputs = append(sealedOutputs, sealed)
	}
	if len(plans) != 0 {
		return PluginTransformResult{}, fmt.Errorf("%w: plugin omitted a planned output", ErrInvalidPluginTransform)
	}
	return PluginTransformResult{Package: request.Package.Digest(), Outputs: sealedOutputs}, nil
}

func validatePluginRequest(request PluginTransformRequest) error {
	if err := request.Package.Digest().Validate(); err != nil || request.Package.Digest().Algorithm() != digest.SHA256 {
		return fmt.Errorf("%w: verified package", ErrInvalidPluginTransform)
	}
	if len(request.Inputs) == 0 || len(request.Inputs) > plugin.MaxInputs {
		return fmt.Errorf("%w: input count", ErrInvalidPluginTransform)
	}
	if len(request.Outputs) == 0 || len(request.Outputs) > plugin.MaxOutputs {
		return fmt.Errorf("%w: output count", ErrInvalidPluginTransform)
	}
	if err := request.PolicyRevision.Validate(); err != nil || request.PolicyRevision.Algorithm() != digest.SHA256 {
		return fmt.Errorf("%w: policy revision", ErrInvalidPluginTransform)
	}

	type inputIdentity struct {
		revision digest.Digest
		payload  string
	}
	seenInputs := make(map[inputIdentity]struct{}, len(request.Inputs))
	var totalInput int64
	for index, input := range request.Inputs {
		payload, err := validatePluginInput(input)
		if err != nil {
			return fmt.Errorf("%w: inputs[%d]: %w", ErrInvalidPluginTransform, index, err)
		}
		identity := inputIdentity{revision: input.Opened.Ref.Revision, payload: input.Payload}
		if _, exists := seenInputs[identity]; exists {
			return fmt.Errorf("%w: duplicate selected input", ErrInvalidPluginTransform)
		}
		seenInputs[identity] = struct{}{}
		if payload.Size > plugin.MaxInputBytes-totalInput {
			return fmt.Errorf("%w: aggregate input size", ErrInvalidPluginTransform)
		}
		totalInput += payload.Size
	}

	seenSlots := make(map[string]struct{}, len(request.Outputs))
	seenUIDs := make(map[artifact.UUID]struct{}, len(request.Outputs))
	for index, output := range request.Outputs {
		if err := (artifact.Metadata{Name: output.Slot}).ValidateExtension(); err != nil {
			return fmt.Errorf("%w: outputs[%d] slot: %w", ErrInvalidPluginTransform, index, err)
		}
		if _, exists := seenSlots[output.Slot]; exists {
			return fmt.Errorf("%w: duplicate output slot %q", ErrInvalidPluginTransform, output.Slot)
		}
		seenSlots[output.Slot] = struct{}{}
		if err := output.UID.Validate(); err != nil {
			return fmt.Errorf("%w: outputs[%d] UID: %w", ErrInvalidPluginTransform, index, err)
		}
		if _, exists := seenUIDs[output.UID]; exists {
			return fmt.Errorf("%w: duplicate output UID", ErrInvalidPluginTransform)
		}
		seenUIDs[output.UID] = struct{}{}
		if err := output.Metadata.Validate(); err != nil {
			return fmt.Errorf("%w: outputs[%d] metadata: %w", ErrInvalidPluginTransform, index, err)
		}
		probe := artifact.PayloadRef{
			Name: output.PayloadName, MediaType: output.PayloadMediaType,
			Digest: digest.FromString("plugin output validation"), Size: 0,
		}
		if err := probe.Validate(); err != nil {
			return fmt.Errorf("%w: outputs[%d] payload: %w", ErrInvalidPluginTransform, index, err)
		}
		if len(output.Edges) > artifact.MaxEdges {
			return fmt.Errorf("%w: outputs[%d] edges", ErrInvalidPluginTransform, index)
		}
		seenEdges := make(map[artifact.UUID]struct{}, len(output.Edges))
		for edgeIndex, edge := range output.Edges {
			if err := edge.Validate(); err != nil {
				return fmt.Errorf("%w: outputs[%d] edges[%d]: %w", ErrInvalidPluginTransform, index, edgeIndex, err)
			}
			if _, exists := seenEdges[edge.ID]; exists {
				return fmt.Errorf("%w: outputs[%d] duplicate edge", ErrInvalidPluginTransform, index)
			}
			seenEdges[edge.ID] = struct{}{}
		}
	}
	return nil
}

func validatePluginInput(selection PluginInputSelection) (artifact.PayloadRef, error) {
	if err := selection.Opened.validateIntegrity(); err != nil {
		return artifact.PayloadRef{}, err
	}
	if err := selection.Opened.Ref.Validate(); err != nil {
		return artifact.PayloadRef{}, err
	}
	if err := selection.Opened.Revision.Validate(); err != nil {
		return artifact.PayloadRef{}, err
	}
	revisionDigest, err := artifact.CanonicalDigest(selection.Opened.Revision)
	if err != nil || revisionDigest != selection.Opened.Ref.Revision {
		return artifact.PayloadRef{}, fmt.Errorf("%w: revision binding", ErrObjectMismatch)
	}
	if err := selection.Opened.Manifest.ValidateForRevision(selection.Opened.Revision); err != nil {
		return artifact.PayloadRef{}, err
	}
	if err := selection.Opened.Grant.Claims.Validate(); err != nil {
		return artifact.PayloadRef{}, err
	}
	if selection.Opened.Grant.Claims.Material != selection.Opened.Ref.Material ||
		selection.Opened.Grant.Identity.RecipientString() != selection.Opened.Manifest.Recipient {
		return artifact.PayloadRef{}, fmt.Errorf("%w: grant or material binding", ErrObjectMismatch)
	}
	if selection.Opened.GrantDescriptor.Digest != selection.Opened.Ref.Grant ||
		selection.Opened.GrantDescriptor.MediaType != artifact.MediaTypeAccessGrant ||
		selection.Opened.MaterialDescriptor.Digest != selection.Opened.Ref.Material ||
		selection.Opened.MaterialDescriptor.MediaType != artifact.MediaTypeEncryptedMaterial {
		return artifact.PayloadRef{}, fmt.Errorf("%w: opened descriptors", ErrObjectMismatch)
	}
	for _, payload := range selection.Opened.Revision.Payloads {
		if payload.Name == selection.Payload {
			return payload, nil
		}
	}
	return artifact.PayloadRef{}, fmt.Errorf("payload %q was not selected from the opened revision", selection.Payload)
}

type pluginRecipientIdentity struct {
	deviceID         artifact.UUID
	subject          string
	x25519Recipient  string
	ed25519PublicKey string
	enrollment       digest.Digest
}

func intersectPluginRecipients(
	inputs []PluginInputSelection,
	verified []artifact.VerifiedDevice,
) ([]artifact.VerifiedDevice, error) {
	if len(inputs) == 0 {
		return nil, ErrEmptyRecipientIntersection
	}
	intersection := make(map[pluginRecipientIdentity]struct{}, len(inputs[0].Opened.Grant.Claims.Recipients))
	for _, recipient := range inputs[0].Opened.Grant.Claims.Recipients {
		intersection[pluginRecipientFromGrant(recipient)] = struct{}{}
	}
	for _, input := range inputs[1:] {
		current := make(map[pluginRecipientIdentity]struct{}, len(input.Opened.Grant.Claims.Recipients))
		for _, recipient := range input.Opened.Grant.Claims.Recipients {
			current[pluginRecipientFromGrant(recipient)] = struct{}{}
		}
		for identity := range intersection {
			if _, exists := current[identity]; !exists {
				delete(intersection, identity)
			}
		}
	}
	if len(intersection) == 0 {
		return nil, ErrEmptyRecipientIntersection
	}

	candidates := make(map[pluginRecipientIdentity]artifact.VerifiedDevice, len(verified))
	for _, device := range verified {
		identity := pluginRecipientFromVerified(device)
		if _, exists := candidates[identity]; exists {
			return nil, fmt.Errorf("%w: duplicate verified recipient", ErrInvalidPluginTransform)
		}
		candidates[identity] = device
	}
	identities := make([]pluginRecipientIdentity, 0, len(intersection))
	for identity := range intersection {
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		return identities[i].deviceID < identities[j].deviceID
	})
	result := make([]artifact.VerifiedDevice, 0, len(identities))
	for _, identity := range identities {
		device, exists := candidates[identity]
		if !exists {
			return nil, fmt.Errorf("%w: missing verified recipient %s", ErrInvalidPluginTransform, identity.deviceID)
		}
		result = append(result, device)
	}
	return result, nil
}

func pluginRecipientFromGrant(recipient artifact.GrantRecipient) pluginRecipientIdentity {
	return pluginRecipientIdentity{
		deviceID: recipient.DeviceID, subject: recipient.Subject,
		x25519Recipient: recipient.X25519Recipient, ed25519PublicKey: string(recipient.Ed25519PublicKey),
		enrollment: recipient.EnrollmentDigest,
	}
}

func pluginRecipientFromVerified(device artifact.VerifiedDevice) pluginRecipientIdentity {
	return pluginRecipientIdentity{
		deviceID: device.DeviceID(), subject: device.Subject(),
		x25519Recipient: device.RecipientString(), ed25519PublicKey: string(device.SigningPublicKey()),
		enrollment: device.AssertionDigest(),
	}
}

type pluginExecutionStorage struct {
	root     string
	inputDir string
	store    *cas.Store
}

func newPluginExecutionStorage(parent string) (*pluginExecutionStorage, error) {
	if err := platform.EnsurePrivateDir(parent); err != nil {
		return nil, fmt.Errorf("prepare plugin temporary parent: %w", err)
	}
	root, err := createPrivatePluginDirectory(parent)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(root)
		}
	}()
	inputDir := filepath.Join(root, "inputs")
	if err := platform.EnsurePrivateDir(inputDir); err != nil {
		return nil, err
	}
	store, err := cas.New(filepath.Join(root, "draft-cas"))
	if err != nil {
		return nil, fmt.Errorf("create plugin draft CAS: %w", err)
	}
	failed = false
	return &pluginExecutionStorage{root: root, inputDir: inputDir, store: store}, nil
}

func (storage *pluginExecutionStorage) Close() error {
	if storage == nil {
		return nil
	}
	var failures []error
	if storage.store != nil {
		if err := storage.store.Close(); err != nil {
			failures = append(failures, err)
		}
		storage.store = nil
	}
	if storage.root != "" {
		if err := os.RemoveAll(storage.root); err != nil {
			failures = append(failures, fmt.Errorf("remove plugin execution storage: %w", err))
		}
		storage.root = ""
	}
	return errors.Join(failures...)
}

func createPrivatePluginDirectory(parent string) (string, error) {
	for range 128 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", fmt.Errorf("generate plugin temporary directory: %w", err)
		}
		path := filepath.Join(parent, "plugin-"+hex.EncodeToString(random[:]))
		if err := os.Mkdir(path, 0o700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return "", fmt.Errorf("create plugin temporary directory: %w", err)
		}
		if err := platform.EnsurePrivateDir(path); err != nil {
			_ = os.RemoveAll(path)
			return "", err
		}
		return path, nil
	}
	return "", errors.New("engine: exhausted plugin temporary directory names")
}

func spoolPluginInput(
	ctx context.Context,
	source artifact.ObjectSource,
	directory string,
	selection PluginInputSelection,
) (plugin.Input, *os.File, error) {
	payload, err := validatePluginInput(selection)
	if err != nil {
		return plugin.Input{}, nil, err
	}
	path, err := randomPluginInputPath(directory)
	if err != nil {
		return plugin.Input{}, nil, err
	}
	writer, err := platform.NewSecureWriter(path)
	if err != nil {
		return plugin.Input{}, nil, err
	}
	defer func() { _ = writer.Abort() }()
	bounded := &exactSizeWriter{destination: writer, remaining: payload.Size}
	if err := selection.Opened.WritePayload(ctx, source, selection.Payload, bounded); err != nil {
		return plugin.Input{}, nil, err
	}
	if bounded.remaining != 0 {
		return plugin.Input{}, nil, fmt.Errorf("%w: plaintext input ended early", ErrObjectMismatch)
	}
	if err := writer.Commit(); err != nil {
		return plugin.Input{}, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return plugin.Input{}, nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	if err := platform.ValidatePrivateFile(path); err != nil {
		return plugin.Input{}, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != payload.Size {
		return plugin.Input{}, nil, fmt.Errorf("%w: spooled input file", ErrObjectMismatch)
	}
	failed = false
	return plugin.Input{Reader: file, Size: payload.Size}, file, nil
}

func randomPluginInputPath(directory string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return filepath.Join(directory, "input-"+hex.EncodeToString(random[:])), nil
}

func closePluginInputs(files []*os.File) error {
	var failures []error
	for _, file := range files {
		if file != nil {
			if err := file.Close(); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

type exactSizeWriter struct {
	destination io.Writer
	remaining   int64
}

func (writer *exactSizeWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > writer.remaining {
		return 0, fmt.Errorf("%w: plaintext input exceeds declared size", ErrObjectMismatch)
	}
	written, err := writer.destination.Write(data)
	writer.remaining -= int64(written)
	return written, err
}

func openPluginDraft(
	ctx context.Context,
	source artifact.ObjectSource,
	expected artifact.Descriptor,
) (io.ReadCloser, error) {
	if source == nil {
		return nil, fmt.Errorf("%w: nil draft source", ErrObjectMismatch)
	}
	if err := expected.Validate(); err != nil || expected.MediaType != plugin.MediaTypeDraft || expected.Size > plugin.MaxOutputBytes {
		return nil, fmt.Errorf("%w: invalid draft descriptor", ErrObjectMismatch)
	}
	reader, descriptor, err := source.Open(ctx, expected.Digest)
	if err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("%w: nil draft reader", ErrObjectMismatch)
	}
	if descriptor != expected {
		_ = reader.Close()
		return nil, fmt.Errorf("%w: draft descriptor substitution", ErrObjectMismatch)
	}
	return &verifiedPluginDraftReader{
		ctx: ctx, source: reader, expected: expected,
		hash: sha256.New(),
	}, nil
}

type verifiedPluginDraftReader struct {
	ctx      context.Context
	source   io.ReadCloser
	expected artifact.Descriptor
	hash     hash.Hash
	read     int64
	verified bool
}

func (reader *verifiedPluginDraftReader) Read(destination []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	if reader.verified {
		return 0, io.EOF
	}
	remaining := reader.expected.Size - reader.read
	limit := int64(len(destination))
	if limit > remaining+1 {
		limit = remaining + 1
	}
	read, err := reader.source.Read(destination[:limit])
	if read < 0 || int64(read) > limit {
		return 0, fmt.Errorf("%w: invalid draft reader count", ErrObjectMismatch)
	}
	if int64(read) > remaining {
		return read, fmt.Errorf("%w: draft exceeds descriptor size", ErrObjectMismatch)
	}
	if read > 0 {
		_, _ = reader.hash.Write(destination[:read])
		reader.read += int64(read)
	}
	if errors.Is(err, io.EOF) {
		if reader.read != reader.expected.Size {
			return read, fmt.Errorf("%w: draft ended at %d, want %d", ErrObjectMismatch, reader.read, reader.expected.Size)
		}
		if actual := digest.NewDigest(digest.SHA256, reader.hash); actual != reader.expected.Digest {
			return read, fmt.Errorf("%w: draft digest is %s, want %s", ErrObjectMismatch, actual, reader.expected.Digest)
		}
		reader.verified = true
		return read, io.EOF
	}
	if err != nil {
		return read, err
	}
	return read, nil
}

func (reader *verifiedPluginDraftReader) Close() error { return reader.source.Close() }

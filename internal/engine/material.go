// Package engine contains the trusted, client-independent orchestration used
// by the application host. It accepts schema-neutral streams and never exposes
// payload bytes through a client transport.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

var (
	ErrInvalidDraft   = errors.New("engine: invalid draft")
	ErrObjectMismatch = errors.New("engine: object mismatch")
)

// PayloadSource is a single-use plaintext stream selected by the host. The
// caller remains responsible for closing an underlying file after SealDraft
// returns; engine never retains the Reader.
type PayloadSource struct {
	Name      string
	MediaType string
	Reader    io.Reader
}

// Draft is the schema-neutral input to sealing. Payload references are derived
// from streams, so callers cannot claim a digest or size they did not supply.
type Draft struct {
	Kind     artifact.Kind
	UID      artifact.UUID
	Schema   artifact.TypeRef
	Metadata artifact.Metadata
	Payloads []PayloadSource
	Edges    []artifact.Edge
}

// Closure is the complete local object closure created while sealing one
// revision. Descriptors are retained for ordered OCI publication.
type Closure struct {
	Chunks    []artifact.Descriptor
	Materials []artifact.Descriptor
	Grants    []artifact.Descriptor
}

// SealedRevision is an immutable revision and its encrypted storage closure.
// Revision contains only stream identities, never plaintext.
type SealedRevision struct {
	Revision artifact.Revision
	Ref      artifact.SealedRef
	Closure  Closure
}

// Sealer owns the cryptographic authority required to issue AccessGrants.
// Recipients must already have passed the configured enrollment verifier.
type Sealer struct {
	Sink       artifact.ObjectSink
	Issuer     *artifact.DeviceIdentity
	Recipients []artifact.VerifiedDevice
}

// SealDraft consumes every selected stream through EOF, constructs its
// canonical Revision, encrypts it and its streams to a fresh material identity,
// and writes an explicit Grant bound to policyRevision.
func (sealer Sealer) SealDraft(
	ctx context.Context,
	draft Draft,
	policyRevision digest.Digest,
) (SealedRevision, error) {
	return sealer.sealDraft(ctx, draft, policyRevision, false)
}

// SealPolicyDraft bootstraps a RegoPolicy Resource whose Grant is bound to the
// digest of that same canonical policy revision. This explicit method avoids a
// magic empty digest in the general sealing API.
func (sealer Sealer) SealPolicyDraft(ctx context.Context, draft Draft) (SealedRevision, error) {
	policyType, err := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/RegoPolicy")
	if err != nil {
		return SealedRevision{}, err
	}
	if draft.Kind != artifact.KindResource || draft.Schema != policyType {
		return SealedRevision{}, fmt.Errorf("%w: policy draft must use the built-in RegoPolicy Resource schema", ErrInvalidDraft)
	}
	return sealer.sealDraft(ctx, draft, "", true)
}

func (sealer Sealer) sealDraft(
	ctx context.Context,
	draft Draft,
	policyRevision digest.Digest,
	selfPolicy bool,
) (SealedRevision, error) {
	if err := ctx.Err(); err != nil {
		return SealedRevision{}, err
	}
	if sealer.Sink == nil || sealer.Issuer == nil || len(sealer.Recipients) == 0 {
		return SealedRevision{}, fmt.Errorf("%w: incomplete sealer", ErrInvalidDraft)
	}
	if !selfPolicy {
		if err := policyRevision.Validate(); err != nil || policyRevision.Algorithm() != digest.SHA256 {
			return SealedRevision{}, fmt.Errorf("%w: policy revision", ErrInvalidDraft)
		}
	}
	if len(draft.Payloads) > artifact.MaxPayloads {
		return SealedRevision{}, fmt.Errorf("%w: too many payloads", ErrInvalidDraft)
	}

	identity, err := artifact.GenerateMaterialIdentity()
	if err != nil {
		return SealedRevision{}, err
	}
	revision := artifact.Revision{
		APIVersion: artifact.APIVersion,
		Kind:       draft.Kind,
		UID:        draft.UID,
		Schema:     draft.Schema,
		Metadata:   cloneMetadata(draft.Metadata),
		Edges:      cloneEdges(draft.Edges),
	}
	manifest := artifact.MaterialManifest{
		APIVersion: artifact.APIVersion,
		Recipient:  identity.RecipientString(),
	}
	closure := Closure{}

	for index, payload := range draft.Payloads {
		if payload.Reader == nil {
			return SealedRevision{}, fmt.Errorf("%w: payloads[%d] has nil reader", ErrInvalidDraft, index)
		}
		stream, streamErr := artifact.EncryptStream(ctx, sealer.Sink, identity, payload.Reader)
		if streamErr != nil {
			return SealedRevision{}, fmt.Errorf("seal payload %q: %w", payload.Name, streamErr)
		}
		revision.Payloads = append(revision.Payloads, artifact.PayloadRef{
			Name:      payload.Name,
			MediaType: payload.MediaType,
			Digest:    stream.Digest,
			Size:      stream.Size,
		})
		manifest.Payloads = append(manifest.Payloads, artifact.MaterialPayload{
			Name:   payload.Name,
			Stream: stream,
		})
		closure.Chunks = appendStreamDescriptors(closure.Chunks, stream)
	}

	revisionBytes, err := artifact.EncodeRevision(revision)
	if err != nil {
		return SealedRevision{}, fmt.Errorf("%w: revision: %v", ErrInvalidDraft, err)
	}
	revisionStream, err := artifact.EncryptStream(ctx, sealer.Sink, identity, bytes.NewReader(revisionBytes))
	if err != nil {
		return SealedRevision{}, fmt.Errorf("seal revision: %w", err)
	}
	manifest.Revision = revisionStream
	closure.Chunks = appendStreamDescriptors(closure.Chunks, revisionStream)
	if selfPolicy {
		policyRevision = revisionStream.Digest
	}

	materialDescriptor, err := artifact.SealMaterialManifest(ctx, sealer.Sink, identity, revision, manifest)
	if err != nil {
		return SealedRevision{}, fmt.Errorf("seal material manifest: %w", err)
	}
	grant, err := artifact.CreateAccessGrant(
		ctx,
		materialDescriptor.Digest,
		policyRevision,
		identity,
		sealer.Issuer,
		append([]artifact.VerifiedDevice(nil), sealer.Recipients...),
	)
	if err != nil {
		return SealedRevision{}, fmt.Errorf("create access grant: %w", err)
	}
	grantBytes, err := artifact.EncodeAccessGrant(grant)
	if err != nil {
		return SealedRevision{}, fmt.Errorf("encode access grant: %w", err)
	}
	grantDescriptor, err := sealer.Sink.Ingest(ctx, artifact.MediaTypeAccessGrant, bytes.NewReader(grantBytes))
	clearBytes(grantBytes)
	if err != nil {
		return SealedRevision{}, fmt.Errorf("store access grant: %w", err)
	}

	return SealedRevision{
		Revision: revision,
		Ref: artifact.SealedRef{
			Revision: revisionStream.Digest,
			Material: materialDescriptor.Digest,
			Grant:    grantDescriptor.Digest,
		},
		Closure: Closure{
			Chunks:    closure.Chunks,
			Materials: []artifact.Descriptor{materialDescriptor},
			Grants:    []artifact.Descriptor{grantDescriptor},
		},
	}, nil
}

// OpenedRevision is a verified revision plus the material identity needed to
// stream a selected payload. No payload is buffered or returned here.
type OpenedRevision struct {
	Ref                artifact.SealedRef
	Revision           artifact.Revision
	Manifest           artifact.MaterialManifest
	Grant              artifact.OpenedGrant
	GrantDescriptor    artifact.Descriptor
	MaterialDescriptor artifact.Descriptor
	integrity          digest.Digest
}

type openedRevisionBinding struct {
	Ref                artifact.SealedRef        `cbor:"ref"`
	Revision           artifact.Revision         `cbor:"revision"`
	Manifest           artifact.MaterialManifest `cbor:"manifest"`
	GrantClaims        artifact.GrantClaims      `cbor:"grantClaims"`
	MaterialRecipient  string                    `cbor:"materialRecipient"`
	GrantDescriptor    artifact.Descriptor       `cbor:"grantDescriptor"`
	MaterialDescriptor artifact.Descriptor       `cbor:"materialDescriptor"`
}

// OpenRevision verifies the exact Grant, material, and canonical Revision
// named by ref before returning metadata. Untrusted object metadata is never
// accepted as a substitute for the caller's reference.
func OpenRevision(
	ctx context.Context,
	source artifact.ObjectSource,
	device *artifact.DeviceIdentity,
	verifier artifact.EnrollmentVerifier,
	ref artifact.SealedRef,
) (OpenedRevision, error) {
	if err := ctx.Err(); err != nil {
		return OpenedRevision{}, err
	}
	if source == nil || device == nil || verifier == nil {
		return OpenedRevision{}, errors.New("engine: nil open dependency")
	}
	if err := ref.Validate(); err != nil {
		return OpenedRevision{}, err
	}
	grantBytes, grantDescriptor, err := readExactObject(ctx, source, ref.Grant, artifact.MediaTypeAccessGrant, artifact.MaxGrantBytes)
	if err != nil {
		return OpenedRevision{}, fmt.Errorf("open access grant: %w", err)
	}
	openedGrant, err := artifact.OpenAccessGrant(ctx, grantBytes, device, verifier)
	clearBytes(grantBytes)
	if err != nil {
		return OpenedRevision{}, err
	}
	if openedGrant.Claims.Material != ref.Material {
		return OpenedRevision{}, fmt.Errorf("%w: grant material", ErrObjectMismatch)
	}
	materialDescriptor, err := inspectExactObject(ctx, source, ref.Material, artifact.MediaTypeEncryptedMaterial, artifact.MaxMaterialBytes+64*1024)
	if err != nil {
		return OpenedRevision{}, fmt.Errorf("inspect material manifest: %w", err)
	}
	manifest, err := artifact.OpenMaterialManifest(ctx, source, openedGrant.Identity, ref.Material, ref.Revision)
	if err != nil {
		return OpenedRevision{}, err
	}
	var revisionBytes bytes.Buffer
	limitedRevision := &limitWriter{Writer: &revisionBytes, Remaining: artifact.MaxRevisionBytes}
	if err := artifact.DecryptStream(ctx, source, openedGrant.Identity, manifest.Revision, limitedRevision); err != nil {
		return OpenedRevision{}, fmt.Errorf("open revision stream: %w", err)
	}
	revision, err := artifact.DecodeRevision(revisionBytes.Bytes())
	clearBytes(revisionBytes.Bytes())
	if err != nil {
		return OpenedRevision{}, err
	}
	if err := manifest.ValidateForRevision(revision); err != nil {
		return OpenedRevision{}, err
	}
	opened := OpenedRevision{
		Ref: ref, Revision: revision, Manifest: manifest, Grant: openedGrant,
		GrantDescriptor: grantDescriptor, MaterialDescriptor: materialDescriptor,
	}
	opened.integrity, err = openedRevisionIntegrity(opened)
	if err != nil {
		return OpenedRevision{}, err
	}
	return opened, nil
}

// WritePayload authenticates and decrypts exactly one named stream. Callers
// must supply a staging destination; publication is their responsibility only
// after this function succeeds.
func (opened OpenedRevision) WritePayload(
	ctx context.Context,
	source artifact.ObjectSource,
	name string,
	destination io.Writer,
) error {
	if err := opened.validateIntegrity(); err != nil {
		return err
	}
	if destination == nil {
		return errors.New("engine: nil payload destination")
	}
	for _, payload := range opened.Manifest.Payloads {
		if payload.Name == name {
			if err := artifact.DecryptStream(ctx, source, opened.Grant.Identity, payload.Stream, destination); err != nil {
				return fmt.Errorf("open payload %q: %w", name, err)
			}
			return nil
		}
	}
	return fmt.Errorf("engine: payload %q not found", name)
}

func (opened OpenedRevision) validateIntegrity() error {
	if opened.integrity == "" {
		return fmt.Errorf("%w: opened revision has no integrity binding", ErrObjectMismatch)
	}
	actual, err := openedRevisionIntegrity(opened)
	if err != nil {
		return err
	}
	if actual != opened.integrity {
		return fmt.Errorf("%w: opened revision was modified after verification", ErrObjectMismatch)
	}
	return nil
}

func openedRevisionIntegrity(opened OpenedRevision) (digest.Digest, error) {
	encoded, err := artifact.MarshalCanonical(openedRevisionBinding{
		Ref:                opened.Ref,
		Revision:           opened.Revision,
		Manifest:           opened.Manifest,
		GrantClaims:        opened.Grant.Claims,
		MaterialRecipient:  opened.Grant.Identity.RecipientString(),
		GrantDescriptor:    opened.GrantDescriptor,
		MaterialDescriptor: opened.MaterialDescriptor,
	})
	if err != nil {
		return "", fmt.Errorf("%w: bind opened revision: %w", ErrObjectMismatch, err)
	}
	return digest.FromBytes(encoded), nil
}

func appendStreamDescriptors(target []artifact.Descriptor, stream artifact.EncryptedStream) []artifact.Descriptor {
	for _, chunk := range stream.Chunks {
		target = append(target, chunk.Ciphertext)
	}
	return target
}

func cloneMetadata(value artifact.Metadata) artifact.Metadata {
	cloned := value
	cloned.Labels = cloneStringMap(value.Labels)
	cloned.Annotations = cloneStringMap(value.Annotations)
	return cloned
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string]string, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func cloneEdges(value []artifact.Edge) []artifact.Edge {
	cloned := append([]artifact.Edge(nil), value...)
	for index := range cloned {
		if cloned[index].Pinned != nil {
			pinned := *cloned[index].Pinned
			cloned[index].Pinned = &pinned
		}
	}
	return cloned
}

func readExactObject(
	ctx context.Context,
	source artifact.ObjectSource,
	objectDigest digest.Digest,
	mediaType string,
	maximum int64,
) (returned []byte, descriptor artifact.Descriptor, returnedErr error) {
	reader, descriptor, err := source.Open(ctx, objectDigest)
	if err != nil {
		return nil, artifact.Descriptor{}, err
	}
	if reader == nil {
		return nil, artifact.Descriptor{}, fmt.Errorf("%w: nil reader", ErrObjectMismatch)
	}
	defer func() {
		if closeErr := reader.Close(); returnedErr == nil && closeErr != nil {
			returned = nil
			descriptor = artifact.Descriptor{}
			returnedErr = closeErr
		}
	}()
	if descriptor.Digest != objectDigest || descriptor.MediaType != mediaType || descriptor.Size <= 0 || descriptor.Size > maximum {
		return nil, artifact.Descriptor{}, fmt.Errorf("%w: descriptor", ErrObjectMismatch)
	}
	data, err := io.ReadAll(io.LimitReader(reader, descriptor.Size+1))
	if err != nil {
		return nil, artifact.Descriptor{}, err
	}
	if int64(len(data)) != descriptor.Size || digest.FromBytes(data) != descriptor.Digest {
		clearBytes(data)
		return nil, artifact.Descriptor{}, fmt.Errorf("%w: content", ErrObjectMismatch)
	}
	return data, descriptor, nil
}

func inspectExactObject(
	ctx context.Context,
	source artifact.ObjectSource,
	objectDigest digest.Digest,
	mediaType string,
	maximum int64,
) (returned artifact.Descriptor, returnedErr error) {
	reader, descriptor, err := source.Open(ctx, objectDigest)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	if reader == nil {
		return artifact.Descriptor{}, fmt.Errorf("%w: nil reader", ErrObjectMismatch)
	}
	defer func() {
		if closeErr := reader.Close(); returnedErr == nil && closeErr != nil {
			returned = artifact.Descriptor{}
			returnedErr = closeErr
		}
	}()
	if descriptor.Digest != objectDigest || descriptor.MediaType != mediaType || descriptor.Size <= 0 || descriptor.Size > maximum {
		return artifact.Descriptor{}, fmt.Errorf("%w: descriptor", ErrObjectMismatch)
	}
	hasher := digest.SHA256.Digester()
	written, err := io.Copy(hasher.Hash(), io.LimitReader(reader, descriptor.Size+1))
	if err != nil {
		return artifact.Descriptor{}, err
	}
	if written != descriptor.Size || hasher.Digest() != descriptor.Digest {
		return artifact.Descriptor{}, fmt.Errorf("%w: content", ErrObjectMismatch)
	}
	return descriptor, nil
}

type limitWriter struct {
	Writer    io.Writer
	Remaining int
}

func (writer *limitWriter) Write(value []byte) (int, error) {
	if len(value) > writer.Remaining {
		return 0, fmt.Errorf("%w: plaintext exceeds limit", ErrObjectMismatch)
	}
	n, err := writer.Writer.Write(value)
	writer.Remaining -= n
	return n, err
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"filippo.io/age"
	"github.com/opencontainers/go-digest"
)

const (
	// MaxMaterialBytes bounds the decrypted canonical manifest kept in memory.
	// Payload bytes are never part of this object.
	MaxMaterialBytes = 16 * 1024 * 1024

	// MaxChunksPerStream limits manifest fan-out as well as decoder allocation.
	MaxChunksPerStream = MaxEdges
)

var (
	ErrMaterialIdentity       = errors.New("invalid material identity")
	ErrMaterialMismatch       = errors.New("material does not match revision")
	ErrInvalidEncryptedObject = errors.New("invalid encrypted object")
)

// MaterialIdentity is the internal, per-material age identity. Its secret is
// deliberately inaccessible outside this package; AccessGrant code wraps it
// for verified device recipients through package-private helpers.
type MaterialIdentity struct {
	value *age.X25519Identity
}

func GenerateMaterialIdentity() (MaterialIdentity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return MaterialIdentity{}, fmt.Errorf("generate material identity: %w", err)
	}
	return MaterialIdentity{value: identity}, nil
}

// RecipientString returns the public X25519 recipient. The zero value returns
// an empty string and is rejected by all cryptographic operations.
func (m MaterialIdentity) RecipientString() string {
	if m.value == nil {
		return ""
	}
	return m.value.Recipient().String()
}

func (m MaterialIdentity) recipient() (age.Recipient, error) {
	if m.value == nil {
		return nil, ErrMaterialIdentity
	}
	return m.value.Recipient(), nil
}

func (m MaterialIdentity) identity() (age.Identity, error) {
	if m.value == nil {
		return nil, ErrMaterialIdentity
	}
	return m.value, nil
}

func (m MaterialIdentity) marshalSecret() (string, error) {
	if m.value == nil {
		return "", ErrMaterialIdentity
	}
	return m.value.String(), nil
}

func parseMaterialIdentity(secret string) (MaterialIdentity, error) {
	identity, err := age.ParseX25519Identity(secret)
	if err != nil {
		return MaterialIdentity{}, fmt.Errorf("%w: %v", ErrMaterialIdentity, err)
	}
	if identity.String() != secret {
		return MaterialIdentity{}, fmt.Errorf("%w: non-canonical secret", ErrMaterialIdentity)
	}
	return MaterialIdentity{value: identity}, nil
}

// ChunkRef records the plaintext boundary represented by one independently
// authenticated age ciphertext object. Offsets make chunk order canonical.
type ChunkRef struct {
	Offset        int64      `cbor:"offset" json:"offset"`
	PlaintextSize int64      `cbor:"plaintextSize" json:"plaintextSize"`
	Ciphertext    Descriptor `cbor:"ciphertext" json:"ciphertext"`
}

func (c ChunkRef) Validate() error {
	if c.Offset < 0 {
		return fmt.Errorf("%w: chunk has negative offset", ErrInvalidArtifact)
	}
	if c.PlaintextSize < 0 {
		return fmt.Errorf("%w: chunk has negative plaintext size", ErrInvalidArtifact)
	}
	if err := c.Ciphertext.Validate(); err != nil {
		return err
	}
	if c.Ciphertext.MediaType != MediaTypeEncryptedChunk {
		return fmt.Errorf("%w: chunk has media type %q", ErrInvalidArtifact, c.Ciphertext.MediaType)
	}
	if c.Ciphertext.Size == 0 {
		return fmt.Errorf("%w: chunk ciphertext is empty", ErrInvalidArtifact)
	}
	return nil
}

// EncryptedStream describes a plaintext stream independently of its chunking.
// Digest and Size are always computed over the complete plaintext stream.
type EncryptedStream struct {
	Digest digest.Digest `cbor:"digest" json:"digest"`
	Size   int64         `cbor:"size" json:"size"`
	Chunks []ChunkRef    `cbor:"chunks" json:"chunks"`
}

func (s EncryptedStream) Validate() error {
	if err := validateDigest(s.Digest); err != nil {
		return fmt.Errorf("%w: stream digest: %v", ErrInvalidArtifact, err)
	}
	if s.Size < 0 {
		return fmt.Errorf("%w: stream has negative size", ErrInvalidArtifact)
	}
	if len(s.Chunks) == 0 || len(s.Chunks) > MaxChunksPerStream {
		return fmt.Errorf("%w: stream must have 1-%d chunks", ErrInvalidArtifact, MaxChunksPerStream)
	}

	canonical := canonicalEncryptedStream(s)
	var offset int64
	for i, chunk := range canonical.Chunks {
		if err := chunk.Validate(); err != nil {
			return fmt.Errorf("%w: chunks[%d]: %v", ErrInvalidArtifact, i, err)
		}
		if chunk.Offset != offset {
			return fmt.Errorf("%w: chunks[%d] starts at %d, want %d", ErrInvalidArtifact, i, chunk.Offset, offset)
		}
		if chunk.PlaintextSize == 0 && (s.Size != 0 || len(s.Chunks) != 1) {
			return fmt.Errorf("%w: only an empty stream may contain an empty chunk", ErrInvalidArtifact)
		}
		if chunk.PlaintextSize > s.Size-offset {
			return fmt.Errorf("%w: chunk boundaries exceed stream size", ErrInvalidArtifact)
		}
		offset += chunk.PlaintextSize
	}
	if offset != s.Size {
		return fmt.Errorf("%w: chunk boundaries total %d, want %d", ErrInvalidArtifact, offset, s.Size)
	}
	return nil
}

// MaterialPayload maps one named logical PayloadRef to its encrypted stream.
// Its digest and size must match the corresponding PayloadRef in Revision.
type MaterialPayload struct {
	Name   string          `cbor:"name" json:"name"`
	Stream EncryptedStream `cbor:"stream" json:"stream"`
}

// MaterialManifest contains no plaintext payload or Revision bytes. The
// canonical object is itself age-encrypted before it reaches ObjectSink.
type MaterialManifest struct {
	APIVersion string            `cbor:"apiVersion" json:"apiVersion"`
	Recipient  string            `cbor:"recipient" json:"recipient"`
	Revision   EncryptedStream   `cbor:"revision" json:"revision"`
	Payloads   []MaterialPayload `cbor:"payloads,omitempty" json:"payloads,omitempty"`
}

func (m MaterialManifest) Validate() error {
	if m.APIVersion != APIVersion {
		return fmt.Errorf("%w: unsupported material API version %q", ErrInvalidArtifact, m.APIVersion)
	}
	recipient, err := age.ParseX25519Recipient(m.Recipient)
	if err != nil || recipient.String() != m.Recipient {
		return fmt.Errorf("%w: material recipient is not canonical age X25519", ErrInvalidArtifact)
	}
	if err := m.Revision.Validate(); err != nil {
		return fmt.Errorf("%w: revision stream: %v", ErrInvalidArtifact, err)
	}
	if len(m.Payloads) > MaxPayloads {
		return fmt.Errorf("%w: material exceeds %d payloads", ErrInvalidArtifact, MaxPayloads)
	}

	names := make(map[string]struct{}, len(m.Payloads))
	for i, payload := range m.Payloads {
		if len(payload.Name) == 0 || len(payload.Name) > 253 || !payloadNamePattern.MatchString(payload.Name) {
			return fmt.Errorf("%w: payloads[%d] has invalid name %q", ErrInvalidArtifact, i, payload.Name)
		}
		if _, exists := names[payload.Name]; exists {
			return fmt.Errorf("%w: duplicate material payload %q", ErrInvalidArtifact, payload.Name)
		}
		names[payload.Name] = struct{}{}
		if err := payload.Stream.Validate(); err != nil {
			return fmt.Errorf("%w: payload %q: %v", ErrInvalidArtifact, payload.Name, err)
		}
	}
	return nil
}

// ValidateForRevision binds a decrypted material manifest to the exact
// canonical Revision and all of its logical PayloadRefs.
func (m MaterialManifest) ValidateForRevision(revision Revision) error {
	if err := m.Validate(); err != nil {
		return err
	}
	revisionBytes, err := EncodeRevision(revision)
	if err != nil {
		return err
	}
	if m.Revision.Digest != digest.FromBytes(revisionBytes) || m.Revision.Size != int64(len(revisionBytes)) {
		return fmt.Errorf("%w: canonical revision stream", ErrMaterialMismatch)
	}
	if len(m.Payloads) != len(revision.Payloads) {
		return fmt.Errorf("%w: payload count", ErrMaterialMismatch)
	}

	payloads := make(map[string]EncryptedStream, len(m.Payloads))
	for _, payload := range m.Payloads {
		payloads[payload.Name] = payload.Stream
	}
	for _, ref := range revision.Payloads {
		stream, exists := payloads[ref.Name]
		if !exists || stream.Digest != ref.Digest || stream.Size != ref.Size {
			return fmt.Errorf("%w: payload %q", ErrMaterialMismatch, ref.Name)
		}
	}
	return nil
}

// SealMaterialManifest encrypts the canonical manifest as one immutable age
// ciphertext object. No plaintext metadata is passed to ObjectSink.
func SealMaterialManifest(
	ctx context.Context,
	sink ObjectSink,
	identity MaterialIdentity,
	revision Revision,
	manifest MaterialManifest,
) (Descriptor, error) {
	if sink == nil {
		return Descriptor{}, errors.New("artifact: nil object sink")
	}
	if manifest.Recipient != identity.RecipientString() {
		return Descriptor{}, fmt.Errorf("%w: manifest recipient", ErrMaterialMismatch)
	}
	if err := manifest.ValidateForRevision(revision); err != nil {
		return Descriptor{}, err
	}
	encoded, err := EncodeMaterialManifest(manifest)
	if err != nil {
		return Descriptor{}, err
	}
	defer clearBytes(encoded)
	recipient, err := identity.recipient()
	if err != nil {
		return Descriptor{}, err
	}
	return ingestAgeObject(ctx, sink, MediaTypeEncryptedMaterial, recipient, bytes.NewReader(encoded))
}

// OpenMaterialManifest authenticates, decrypts, and strictly decodes an
// encrypted material manifest addressed by digest.
func OpenMaterialManifest(
	ctx context.Context,
	source ObjectSource,
	identity MaterialIdentity,
	materialDigest digest.Digest,
	expectedRevision digest.Digest,
) (MaterialManifest, error) {
	if source == nil {
		return MaterialManifest{}, errors.New("artifact: nil object source")
	}
	if err := validateDigest(materialDigest); err != nil {
		return MaterialManifest{}, fmt.Errorf("%w: material digest: %v", ErrInvalidArtifact, err)
	}
	if err := validateDigest(expectedRevision); err != nil {
		return MaterialManifest{}, fmt.Errorf("%w: revision digest: %v", ErrInvalidArtifact, err)
	}
	ageIdentity, err := identity.identity()
	if err != nil {
		return MaterialManifest{}, err
	}

	var plaintext limitedBuffer
	plaintext.limit = MaxMaterialBytes
	if _, err := decryptAgeObject(ctx, source, materialDigest, MediaTypeEncryptedMaterial, unknownExpectedObjectSize, ageIdentity, &plaintext); err != nil {
		return MaterialManifest{}, fmt.Errorf("open material manifest: %w", err)
	}
	defer clearBytes(plaintext.Bytes())
	manifest, err := DecodeMaterialManifest(plaintext.Bytes())
	if err != nil {
		return MaterialManifest{}, err
	}
	if manifest.Recipient != identity.RecipientString() {
		return MaterialManifest{}, fmt.Errorf("%w: manifest recipient", ErrMaterialMismatch)
	}
	if manifest.Revision.Digest != expectedRevision {
		return MaterialManifest{}, fmt.Errorf("%w: revision digest", ErrMaterialMismatch)
	}
	return manifest, nil
}

func canonicalMaterialManifest(manifest MaterialManifest) MaterialManifest {
	canonical := manifest
	canonical.Revision = canonicalEncryptedStream(manifest.Revision)
	canonical.Payloads = append([]MaterialPayload(nil), manifest.Payloads...)
	for i := range canonical.Payloads {
		canonical.Payloads[i].Stream = canonicalEncryptedStream(canonical.Payloads[i].Stream)
	}
	sort.Slice(canonical.Payloads, func(i, j int) bool {
		return canonical.Payloads[i].Name < canonical.Payloads[j].Name
	})
	return canonical
}

func canonicalEncryptedStream(stream EncryptedStream) EncryptedStream {
	canonical := stream
	canonical.Chunks = append([]ChunkRef(nil), stream.Chunks...)
	sort.Slice(canonical.Chunks, func(i, j int) bool {
		return canonical.Chunks[i].Offset < canonical.Chunks[j].Offset
	})
	return canonical
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		return 0, fmt.Errorf("%w: manifest exceeds %d bytes", ErrInvalidArtifact, b.limit)
	}
	if len(p) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		return remaining, fmt.Errorf("%w: manifest exceeds %d bytes", ErrInvalidArtifact, b.limit)
	}
	return b.Buffer.Write(p)
}

var _ io.Writer = (*limitedBuffer)(nil)

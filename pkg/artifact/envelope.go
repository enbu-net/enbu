package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// SealEncryptedEnvelope encrypts a bounded host-owned metadata stream with a
// Material identity and stores the resulting age object. Payload streams and
// material manifests have stronger dedicated APIs and are deliberately not
// accepted here.
func SealEncryptedEnvelope(
	ctx context.Context,
	sink ObjectSink,
	identity MaterialIdentity,
	mediaType string,
	plaintext io.Reader,
) (Descriptor, error) {
	if sink == nil {
		return Descriptor{}, errors.New("artifact: nil object sink")
	}
	if plaintext == nil {
		return Descriptor{}, errors.New("artifact: nil plaintext reader")
	}
	if !isEncryptedEnvelopeMediaType(mediaType) {
		return Descriptor{}, fmt.Errorf("%w: unsupported encrypted envelope media type %q", ErrInvalidArtifact, mediaType)
	}
	recipient, err := identity.recipient()
	if err != nil {
		return Descriptor{}, err
	}
	return ingestAgeObject(ctx, sink, mediaType, recipient, plaintext)
}

// OpenEncryptedEnvelope authenticates an exact encrypted metadata descriptor
// before returning. Callers must write to staging storage and publish no
// plaintext until this function has consumed the ciphertext through EOF.
func OpenEncryptedEnvelope(
	ctx context.Context,
	source ObjectSource,
	identity MaterialIdentity,
	descriptor Descriptor,
	destination io.Writer,
) error {
	if source == nil {
		return errors.New("artifact: nil object source")
	}
	if destination == nil {
		return errors.New("artifact: nil plaintext destination")
	}
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if descriptor.Size == 0 || !isEncryptedEnvelopeMediaType(descriptor.MediaType) {
		return fmt.Errorf("%w: unsupported encrypted envelope descriptor", ErrInvalidArtifact)
	}
	ageIdentity, err := identity.identity()
	if err != nil {
		return err
	}
	_, err = decryptAgeObject(
		ctx,
		source,
		descriptor.Digest,
		descriptor.MediaType,
		descriptor.Size,
		ageIdentity,
		destination,
	)
	if err != nil {
		return fmt.Errorf("open encrypted envelope: %w", err)
	}
	return nil
}

func isEncryptedEnvelopeMediaType(mediaType string) bool {
	switch mediaType {
	case MediaTypeEncryptedCommit, MediaTypeEncryptedAuditSegment:
		return true
	default:
		return false
	}
}

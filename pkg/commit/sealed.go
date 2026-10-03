package commit

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

// SealedCommit is a newly encrypted Commit plus the private capability needed
// to issue or rewrap Grants for that exact ciphertext. The Material identity
// is intentionally not exposed, preventing accidental reuse for another
// Commit through this API.
type SealedCommit struct {
	id         digest.Digest
	descriptor artifact.Descriptor
	identity   artifact.MaterialIdentity
}

func (s SealedCommit) CommitID() digest.Digest         { return s.id }
func (s SealedCommit) Descriptor() artifact.Descriptor { return s.descriptor }
func (s SealedCommit) MaterialRecipient() string       { return s.identity.RecipientString() }

// CreateAccessGrant wraps this Commit's private identity for the exact
// verified recipient set. Repeating this method rewraps the same encrypted
// Commit; confidentiality narrowing still requires sealing a new Commit.
func (s SealedCommit) CreateAccessGrant(
	ctx context.Context,
	policy digest.Digest,
	issuer *artifact.DeviceIdentity,
	recipients []artifact.VerifiedDevice,
) (artifact.AccessGrant, error) {
	if err := validateDigest(s.id); err != nil {
		return artifact.AccessGrant{}, fmt.Errorf("%w: uninitialized sealed Commit", ErrInvalidCommit)
	}
	if err := s.descriptor.Validate(); err != nil || s.descriptor.MediaType != artifact.MediaTypeEncryptedCommit ||
		s.descriptor.Size == 0 || s.identity.RecipientString() == "" {
		return artifact.AccessGrant{}, fmt.Errorf("%w: invalid sealed Commit capability", ErrInvalidCommit)
	}
	return artifact.CreateAccessGrant(ctx, s.descriptor.Digest, policy, s.identity, issuer, recipients)
}

// SealCommit signs a Commit and encrypts its exact canonical signed plaintext
// to a newly generated per-Commit Material identity. The logical Commit ID is
// independent of the randomized ciphertext descriptor.
func SealCommit(
	ctx context.Context,
	sink artifact.ObjectSink,
	value Commit,
	signer Signer,
	author artifact.VerifiedDevice,
) (SealedCommit, error) {
	encoded, err := SignCommit(value, signer, author)
	if err != nil {
		return SealedCommit{}, err
	}
	defer wipe(encoded)
	commitID := digest.FromBytes(encoded)
	identity, err := artifact.GenerateMaterialIdentity()
	if err != nil {
		return SealedCommit{}, fmt.Errorf("generate Commit identity: %w", err)
	}
	descriptor, err := artifact.SealEncryptedEnvelope(
		ctx,
		sink,
		identity,
		artifact.MediaTypeEncryptedCommit,
		bytes.NewReader(encoded),
	)
	if err != nil {
		return SealedCommit{}, fmt.Errorf("seal Commit: %w", err)
	}
	return SealedCommit{id: commitID, descriptor: descriptor, identity: identity}, nil
}

// OpenCommit authenticates and decrypts an exact encrypted descriptor, bounds
// the plaintext before allocation, verifies the historical signing-key
// binding, and finally binds it to the announced logical Commit ID.
func OpenCommit(
	ctx context.Context,
	source artifact.ObjectSource,
	grant artifact.OpenedGrant,
	descriptor artifact.Descriptor,
	expectedID digest.Digest,
	verifier artifact.EnrollmentVerifier,
) (VerifiedCommit, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedCommit{}, err
	}
	if err := validateDigest(expectedID); err != nil {
		return VerifiedCommit{}, fmt.Errorf("%w: expected Commit ID: %v", ErrInvalidCommit, err)
	}
	if descriptor.MediaType != artifact.MediaTypeEncryptedCommit {
		return VerifiedCommit{}, fmt.Errorf("%w: encrypted Commit media type", ErrInvalidCommit)
	}
	if grant.Claims.Material != descriptor.Digest || grant.Identity.RecipientString() == "" {
		return VerifiedCommit{}, fmt.Errorf("%w: Grant does not bind encrypted Commit", ErrInvalidCommit)
	}

	plaintext := &boundedBuffer{limit: MaxCommitBytes}
	if err := artifact.OpenEncryptedEnvelope(ctx, source, grant.Identity, descriptor, plaintext); err != nil {
		return VerifiedCommit{}, fmt.Errorf("open Commit envelope: %w", err)
	}
	defer wipe(plaintext.Bytes())
	verified, err := VerifySignedCommit(ctx, plaintext.Bytes(), verifier)
	if err != nil {
		return VerifiedCommit{}, err
	}
	if verified.Digest() != expectedID {
		return VerifiedCommit{}, fmt.Errorf("%w: logical Commit ID mismatch", ErrInvalidCommit)
	}
	return verified, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		return 0, fmt.Errorf("%w: decrypted Commit exceeds %d bytes", ErrInvalidCommit, b.limit)
	}
	if len(value) > remaining {
		written, _ := b.Buffer.Write(value[:remaining])
		return written, fmt.Errorf("%w: decrypted Commit exceeds %d bytes", ErrInvalidCommit, b.limit)
	}
	return b.Buffer.Write(value)
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ io.Writer = (*boundedBuffer)(nil)

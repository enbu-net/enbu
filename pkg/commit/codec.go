package commit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const signatureDomain = "enbu.net/commit/v1\x00"

type signaturePayload struct {
	Commit           Commit            `cbor:"commit"`
	SigningKey       ed25519.PublicKey `cbor:"signingKey"`
	AuthorEnrollment []byte            `cbor:"authorEnrollment"`
}

// SignCommit validates and signs a canonical Commit. The Signer Device ID and
// public key are checked before and after signing so a faulty key adapter can't
// silently emit an unverifiable object.
func SignCommit(value Commit, signer Signer, author artifact.VerifiedDevice) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: nil signer", ErrInvalidSignature)
	}
	canonical := canonicalCommit(value)
	if err := canonical.Validate(); err != nil {
		return nil, err
	}
	if signer.DeviceID() != canonical.DeviceID {
		return nil, fmt.Errorf("%w: signer Device ID does not match commit", ErrSigningKeyBinding)
	}
	publicKey := append(ed25519.PublicKey(nil), signer.SigningPublicKey()...)
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: signer returned an invalid Ed25519 public key", ErrSigningKeyBinding)
	}
	if author.DeviceID() != canonical.DeviceID || author.Subject() != canonical.Actor ||
		!publicKeysEqual(author.SigningPublicKey(), publicKey) {
		return nil, fmt.Errorf("%w: author enrollment does not match commit signer", ErrSigningKeyBinding)
	}
	authorEnrollment := author.EnrollmentAssertion()
	if len(authorEnrollment) == 0 || len(authorEnrollment) > artifact.MaxEnrollmentAssertionBytes {
		return nil, fmt.Errorf("%w: invalid author enrollment size", ErrSigningKeyBinding)
	}
	message, err := signatureMessage(canonical, publicKey, authorEnrollment)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(append([]byte(nil), message...))
	if err != nil {
		return nil, fmt.Errorf("sign commit: %w", err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return nil, fmt.Errorf("%w: signer output", ErrInvalidSignature)
	}
	return EncodeSignedCommit(SignedCommit{
		Commit:           canonical,
		SigningKey:       publicKey,
		AuthorEnrollment: authorEnrollment,
		Signature:        append([]byte(nil), signature...),
	})
}

// EncodeSignedCommit emits the sole canonical signed-plaintext representation.
// It proves self-consistency only; use VerifySignedCommit to authenticate the
// embedded key against a historical actor/device binding.
func EncodeSignedCommit(value SignedCommit) ([]byte, error) {
	canonical := value
	canonical.Commit = canonicalCommit(value.Commit)
	canonical.SigningKey = append(ed25519.PublicKey(nil), value.SigningKey...)
	canonical.AuthorEnrollment = append([]byte(nil), value.AuthorEnrollment...)
	canonical.Signature = append([]byte(nil), value.Signature...)
	if err := validateSignedCommit(canonical); err != nil {
		return nil, err
	}
	encoded, err := artifact.MarshalCanonical(canonical)
	if err != nil {
		return nil, fmt.Errorf("encode signed commit: %w", err)
	}
	if len(encoded) > MaxCommitBytes {
		return nil, fmt.Errorf("%w: signed commit exceeds %d encoded bytes", ErrInvalidCommit, MaxCommitBytes)
	}
	return encoded, nil
}

// DecodeSignedCommit rejects malformed, oversized, unknown-field, non-
// canonical, and self-inconsistent signed plaintext. The embedded key remains
// untrusted until VerifySignedCommit succeeds.
func DecodeSignedCommit(data []byte) (SignedCommit, error) {
	if len(data) == 0 || len(data) > MaxCommitBytes {
		return SignedCommit{}, fmt.Errorf("%w: signed commit size", ErrInvalidCommit)
	}
	var decoded SignedCommit
	if err := artifact.UnmarshalStrict(data, &decoded); err != nil {
		return SignedCommit{}, fmt.Errorf("decode signed commit: %w", err)
	}
	canonical, err := EncodeSignedCommit(decoded)
	if err != nil {
		return SignedCommit{}, err
	}
	if !bytes.Equal(data, canonical) {
		return SignedCommit{}, ErrNonCanonicalCommit
	}
	decoded.Commit = cloneCommit(decoded.Commit)
	decoded.SigningKey = append(ed25519.PublicKey(nil), decoded.SigningKey...)
	decoded.AuthorEnrollment = append([]byte(nil), decoded.AuthorEnrollment...)
	decoded.Signature = append([]byte(nil), decoded.Signature...)
	return decoded, nil
}

func validateSignedCommit(value SignedCommit) error {
	if err := value.Commit.Validate(); err != nil {
		return err
	}
	if len(value.SigningKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid Ed25519 public key size", ErrInvalidSignature)
	}
	if len(value.AuthorEnrollment) == 0 || len(value.AuthorEnrollment) > artifact.MaxEnrollmentAssertionBytes {
		return fmt.Errorf("%w: invalid author enrollment size", ErrSigningKeyBinding)
	}
	if len(value.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid Ed25519 signature size", ErrInvalidSignature)
	}
	message, err := signatureMessage(value.Commit, value.SigningKey, value.AuthorEnrollment)
	if err != nil {
		return err
	}
	if !ed25519.Verify(value.SigningKey, message, value.Signature) {
		return ErrInvalidSignature
	}
	return nil
}

func signatureMessage(value Commit, publicKey ed25519.PublicKey, authorEnrollment []byte) ([]byte, error) {
	payload, err := artifact.MarshalCanonical(signaturePayload{
		Commit:           canonicalCommit(value),
		SigningKey:       append(ed25519.PublicKey(nil), publicKey...),
		AuthorEnrollment: append([]byte(nil), authorEnrollment...),
	})
	if err != nil {
		return nil, fmt.Errorf("encode commit signature payload: %w", err)
	}
	message := make([]byte, 0, len(signatureDomain)+len(payload))
	message = append(message, signatureDomain...)
	message = append(message, payload...)
	return message, nil
}

// VerifiedCommit is a type-state value whose signature key has exactly one
// historical binding to the commit actor and Device ID.
type VerifiedCommit struct {
	digest      digest.Digest
	signerKeyID digest.Digest
	encodedSize int
	value       Commit
}

// VerifySignedCommit authenticates a canonical signed plaintext against its
// embedded immutable enrollment assertion. Verification is local and does not
// depend on mutable account or network state.
func VerifySignedCommit(ctx context.Context, data []byte, verifier artifact.EnrollmentVerifier) (VerifiedCommit, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedCommit{}, err
	}
	decoded, err := DecodeSignedCommit(data)
	if err != nil {
		return VerifiedCommit{}, err
	}
	if verifier == nil {
		return VerifiedCommit{}, fmt.Errorf("%w: nil enrollment verifier", ErrSigningKeyBinding)
	}
	author, err := artifact.VerifyEnrollment(ctx, verifier, decoded.AuthorEnrollment)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifiedCommit{}, ctxErr
		}
		return VerifiedCommit{}, fmt.Errorf("%w: author enrollment: %w", ErrSigningKeyBinding, err)
	}
	if author.DeviceID() != decoded.Commit.DeviceID || author.Subject() != decoded.Commit.Actor ||
		!publicKeysEqual(author.SigningPublicKey(), decoded.SigningKey) {
		return VerifiedCommit{}, ErrSigningKeyBinding
	}
	message, err := signatureMessage(decoded.Commit, author.SigningPublicKey(), decoded.AuthorEnrollment)
	if err != nil {
		return VerifiedCommit{}, err
	}
	if !ed25519.Verify(author.SigningPublicKey(), message, decoded.Signature) {
		return VerifiedCommit{}, ErrInvalidSignature
	}
	return VerifiedCommit{
		digest:      digest.FromBytes(data),
		signerKeyID: digest.FromBytes(decoded.SigningKey),
		encodedSize: len(data),
		value:       cloneCommit(decoded.Commit),
	}, nil
}

// Digest returns the stable ID of the canonical signed plaintext. Encryption
// and its CAS descriptor are separate storage identities.
func (v VerifiedCommit) Digest() digest.Digest {
	return v.digest
}

// SignerKeyID returns the SHA-256 fingerprint of the authenticated Ed25519
// public key embedded in this Commit.
func (v VerifiedCommit) SignerKeyID() digest.Digest {
	return v.signerKeyID
}

// Commit returns a defensive copy of the authenticated plaintext.
func (v VerifiedCommit) Commit() Commit {
	return cloneCommit(v.value)
}

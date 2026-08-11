// Package enrollment implements the bounded, offline-verifiable assertion
// format consumed by artifact.VerifyEnrollment. Issuing assertions belongs to
// a trusted identity provider; the application host only holds public keys.
package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	APIVersion = "enrollments.enbu.net/v1alpha1"
	Kind       = "DeviceEnrollment"
)

var ErrInvalidAssertion = errors.New("enrollment: invalid assertion")

type Claims struct {
	APIVersion       string            `cbor:"apiVersion"`
	Kind             string            `cbor:"kind"`
	Issuer           string            `cbor:"issuer"`
	KeyID            digest.Digest     `cbor:"keyID"`
	DeviceID         artifact.UUID     `cbor:"deviceID"`
	Subject          string            `cbor:"subject"`
	X25519Recipient  string            `cbor:"x25519Recipient"`
	Ed25519PublicKey ed25519.PublicKey `cbor:"ed25519PublicKey"`
}

type Assertion struct {
	Claims    Claims `cbor:"claims"`
	Signature []byte `cbor:"signature"`
}

// Authority is safe shared configuration. KeyID is derived from PublicKey
// and prevents silent key substitution under one issuer name.
type Authority struct {
	Issuer    string            `cbor:"issuer"`
	KeyID     digest.Digest     `cbor:"keyID"`
	PublicKey ed25519.PublicKey `cbor:"publicKey"`
}

// Signer is the minimal issuer capability. DeviceIdentity implements it, so a
// workspace's initial device can bootstrap a trusted local authority without
// exporting its Ed25519 private key.
type Signer interface {
	SigningPublicKey() ed25519.PublicKey
	Sign([]byte) ([]byte, error)
}

func NewAuthority(issuer string, publicKey ed25519.PublicKey) (Authority, error) {
	if err := validateIssuer(issuer); err != nil {
		return Authority{}, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return Authority{}, fmt.Errorf("%w: authority public key", ErrInvalidAssertion)
	}
	key := append(ed25519.PublicKey(nil), publicKey...)
	return Authority{Issuer: issuer, KeyID: digest.FromBytes(key), PublicKey: key}, nil
}

// Sign is intended for enrollment issuers and deterministic integration
// fixtures. Device clients never receive the issuer private key.
func Sign(claims Claims, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: issuer private key", ErrInvalidAssertion)
	}
	return SignWithSigner(claims, privateKeySigner{key: privateKey})
}

// SignWithSigner issues through a key capability and verifies the returned
// signature before constructing the assertion.
func SignWithSigner(claims Claims, signer Signer) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: nil issuer signer", ErrInvalidAssertion)
	}
	publicKey := append(ed25519.PublicKey(nil), signer.SigningPublicKey()...)
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: issuer public key", ErrInvalidAssertion)
	}
	if claims.APIVersion == "" {
		claims.APIVersion = APIVersion
	}
	if claims.Kind == "" {
		claims.Kind = Kind
	}
	authority, err := NewAuthority(claims.Issuer, publicKey)
	if err != nil {
		return nil, err
	}
	if claims.KeyID == "" {
		claims.KeyID = authority.KeyID
	}
	if err := claims.validate(); err != nil {
		return nil, err
	}
	if claims.KeyID != authority.KeyID {
		return nil, fmt.Errorf("%w: issuer key ID mismatch", ErrInvalidAssertion)
	}
	encodedClaims, err := artifact.MarshalCanonical(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: encode claims: %v", ErrInvalidAssertion, err)
	}
	signature, err := signer.Sign(append([]byte(nil), encodedClaims...))
	if err != nil {
		return nil, fmt.Errorf("%w: issuer signature: %v", ErrInvalidAssertion, err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, encodedClaims, signature) {
		return nil, fmt.Errorf("%w: issuer signer output", ErrInvalidAssertion)
	}
	assertion := Assertion{Claims: claims, Signature: append([]byte(nil), signature...)}
	encoded, err := artifact.MarshalCanonical(assertion)
	if err != nil {
		return nil, fmt.Errorf("%w: encode assertion: %v", ErrInvalidAssertion, err)
	}
	if len(encoded) > artifact.MaxEnrollmentAssertionBytes {
		return nil, fmt.Errorf("%w: assertion size", ErrInvalidAssertion)
	}
	return encoded, nil
}

type privateKeySigner struct{ key ed25519.PrivateKey }

func (signer privateKeySigner) SigningPublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), signer.key.Public().(ed25519.PublicKey)...)
}

func (signer privateKeySigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(signer.key, message), nil
}

type Verifier struct {
	authorities map[digest.Digest]Authority
}

func NewVerifier(authorities []Authority) (*Verifier, error) {
	if len(authorities) == 0 || len(authorities) > 64 {
		return nil, fmt.Errorf("%w: authority count", ErrInvalidAssertion)
	}
	verified := make(map[digest.Digest]Authority, len(authorities))
	for index, authority := range authorities {
		expected, err := NewAuthority(authority.Issuer, authority.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("authorities[%d]: %w", index, err)
		}
		if authority.KeyID != expected.KeyID {
			return nil, fmt.Errorf("%w: authorities[%d] key ID", ErrInvalidAssertion, index)
		}
		if existing, ok := verified[authority.KeyID]; ok && existing.Issuer != authority.Issuer {
			return nil, fmt.Errorf("%w: one key has multiple issuers", ErrInvalidAssertion)
		}
		verified[authority.KeyID] = expected
	}
	return &Verifier{authorities: verified}, nil
}

func (verifier *Verifier) VerifyEnrollment(ctx context.Context, encoded []byte) (artifact.EnrollmentClaims, error) {
	if ctx == nil {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: nil context", ErrInvalidAssertion)
	}
	if err := ctx.Err(); err != nil {
		return artifact.EnrollmentClaims{}, err
	}
	if verifier == nil || len(verifier.authorities) == 0 {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: uninitialized verifier", ErrInvalidAssertion)
	}
	if len(encoded) == 0 || len(encoded) > artifact.MaxEnrollmentAssertionBytes {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: assertion size", ErrInvalidAssertion)
	}
	var assertion Assertion
	if err := artifact.UnmarshalStrict(encoded, &assertion); err != nil {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: decode: %v", ErrInvalidAssertion, err)
	}
	canonical, err := artifact.MarshalCanonical(assertion)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: non-canonical assertion", ErrInvalidAssertion)
	}
	if err := assertion.Claims.validate(); err != nil {
		return artifact.EnrollmentClaims{}, err
	}
	if len(assertion.Signature) != ed25519.SignatureSize {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: signature size", ErrInvalidAssertion)
	}
	authority, ok := verifier.authorities[assertion.Claims.KeyID]
	if !ok || authority.Issuer != assertion.Claims.Issuer {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: untrusted issuer", ErrInvalidAssertion)
	}
	claimsBytes, err := artifact.MarshalCanonical(assertion.Claims)
	if err != nil {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: claims encoding", ErrInvalidAssertion)
	}
	if !ed25519.Verify(authority.PublicKey, claimsBytes, assertion.Signature) {
		return artifact.EnrollmentClaims{}, fmt.Errorf("%w: signature", ErrInvalidAssertion)
	}
	return artifact.EnrollmentClaims{
		DeviceID:         assertion.Claims.DeviceID,
		Subject:          assertion.Claims.Subject,
		X25519Recipient:  assertion.Claims.X25519Recipient,
		Ed25519PublicKey: append(ed25519.PublicKey(nil), assertion.Claims.Ed25519PublicKey...),
	}, nil
}

func (claims Claims) validate() error {
	if claims.APIVersion != APIVersion || claims.Kind != Kind {
		return fmt.Errorf("%w: unsupported type", ErrInvalidAssertion)
	}
	if err := validateIssuer(claims.Issuer); err != nil {
		return err
	}
	if err := claims.KeyID.Validate(); err != nil {
		return fmt.Errorf("%w: key ID: %v", ErrInvalidAssertion, err)
	}
	if err := claims.DeviceID.Validate(); err != nil {
		return fmt.Errorf("%w: device ID: %v", ErrInvalidAssertion, err)
	}
	if err := validateSubject(claims.Subject); err != nil {
		return err
	}
	if claims.X25519Recipient == "" || len(claims.X25519Recipient) > 256 {
		return fmt.Errorf("%w: X25519 recipient", ErrInvalidAssertion)
	}
	if len(claims.Ed25519PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: device signing key", ErrInvalidAssertion)
	}
	return nil
}

func validateIssuer(value string) error {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.ContainsAny(value, "/:@\x00") || !strings.Contains(value, ".") {
		return fmt.Errorf("%w: issuer must be a lowercase DNS name", ErrInvalidAssertion)
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: issuer DNS label", ErrInvalidAssertion)
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return fmt.Errorf("%w: issuer DNS character", ErrInvalidAssertion)
		}
	}
	return nil
}

func validateSubject(value string) error {
	if value == "" || len(value) > 253 || strings.ContainsRune(value, 0) || !strings.Contains(value, ":") {
		return fmt.Errorf("%w: provider-qualified subject", ErrInvalidAssertion)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%w: subject control character", ErrInvalidAssertion)
		}
	}
	return nil
}

var _ artifact.EnrollmentVerifier = (*Verifier)(nil)

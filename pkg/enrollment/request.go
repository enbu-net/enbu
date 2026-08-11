package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"filippo.io/age"
	"github.com/enbu-net/enbu/pkg/artifact"
)

const (
	RequestKind     = "DeviceEnrollmentRequest"
	MaxRequestBytes = 64 * 1024

	requestSigningDomain = "enbu.net/device-enrollment-request/v1\x00"
)

var ErrInvalidRequest = errors.New("enrollment: invalid device request")

// RequestClaims are public device keys proposed for owner approval. The
// candidate signs the complete binding to prove control of its Ed25519 key;
// the owner later issues the workspace-authority assertion.
type RequestClaims struct {
	APIVersion       string            `cbor:"apiVersion" json:"apiVersion"`
	Kind             string            `cbor:"kind" json:"kind"`
	DeviceID         artifact.UUID     `cbor:"deviceID" json:"deviceID"`
	Subject          string            `cbor:"subject" json:"subject"`
	X25519Recipient  string            `cbor:"x25519Recipient" json:"x25519Recipient"`
	Ed25519PublicKey ed25519.PublicKey `cbor:"ed25519PublicKey" json:"ed25519PublicKey"`
}

type Request struct {
	Claims    RequestClaims `cbor:"claims" json:"claims"`
	Signature []byte        `cbor:"signature" json:"signature"`
}

func CreateRequest(ctx context.Context, signer Signer, deviceID artifact.UUID, subject, recipient string) ([]byte, error) {
	if ctx == nil || signer == nil {
		return nil, fmt.Errorf("%w: missing context or signer", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	claims := RequestClaims{
		APIVersion: APIVersion, Kind: RequestKind, DeviceID: deviceID, Subject: subject,
		X25519Recipient: recipient, Ed25519PublicKey: append(ed25519.PublicKey(nil), signer.SigningPublicKey()...),
	}
	if err := claims.validate(); err != nil {
		return nil, err
	}
	message, err := requestSigningMessage(claims)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(message)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(claims.Ed25519PublicKey, message, signature) {
		return nil, fmt.Errorf("%w: signer output", ErrInvalidRequest)
	}
	encoded, err := artifact.MarshalCanonical(Request{Claims: claims, Signature: append([]byte(nil), signature...)})
	if err != nil || len(encoded) > MaxRequestBytes {
		return nil, fmt.Errorf("%w: encoding", ErrInvalidRequest)
	}
	return encoded, nil
}

func VerifyRequest(ctx context.Context, encoded []byte) (RequestClaims, error) {
	if ctx == nil {
		return RequestClaims{}, fmt.Errorf("%w: nil context", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return RequestClaims{}, err
	}
	if len(encoded) == 0 || len(encoded) > MaxRequestBytes {
		return RequestClaims{}, fmt.Errorf("%w: size", ErrInvalidRequest)
	}
	var request Request
	if err := artifact.UnmarshalStrict(encoded, &request); err != nil {
		return RequestClaims{}, fmt.Errorf("%w: decode: %v", ErrInvalidRequest, err)
	}
	canonical, err := artifact.MarshalCanonical(request)
	if err != nil || !bytes.Equal(encoded, canonical) || len(request.Signature) != ed25519.SignatureSize {
		return RequestClaims{}, fmt.Errorf("%w: canonical encoding or signature size", ErrInvalidRequest)
	}
	if err := request.Claims.validate(); err != nil {
		return RequestClaims{}, err
	}
	message, err := requestSigningMessage(request.Claims)
	if err != nil || !ed25519.Verify(request.Claims.Ed25519PublicKey, message, request.Signature) {
		return RequestClaims{}, fmt.Errorf("%w: signature", ErrInvalidRequest)
	}
	claims := request.Claims
	claims.Ed25519PublicKey = append(ed25519.PublicKey(nil), claims.Ed25519PublicKey...)
	return claims, nil
}

func (claims RequestClaims) validate() error {
	if claims.APIVersion != APIVersion || claims.Kind != RequestKind {
		return fmt.Errorf("%w: unsupported type", ErrInvalidRequest)
	}
	if err := claims.DeviceID.Validate(); err != nil {
		return fmt.Errorf("%w: device ID", ErrInvalidRequest)
	}
	if err := validateSubject(claims.Subject); err != nil {
		return fmt.Errorf("%w: subject", ErrInvalidRequest)
	}
	if _, err := age.ParseX25519Recipient(claims.X25519Recipient); err != nil {
		return fmt.Errorf("%w: X25519 recipient", ErrInvalidRequest)
	}
	if len(claims.Ed25519PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signing key", ErrInvalidRequest)
	}
	return nil
}

func requestSigningMessage(claims RequestClaims) ([]byte, error) {
	encoded, err := artifact.MarshalCanonical(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: claims", ErrInvalidRequest)
	}
	return append([]byte(requestSigningDomain), encoded...), nil
}

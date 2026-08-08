package artifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
)

type memoryCredentialStore struct {
	protection CredentialProtection
	value      []byte
}

type enrollmentVerifierFunc func(context.Context, []byte) (EnrollmentClaims, error)

func (f enrollmentVerifierFunc) VerifyEnrollment(ctx context.Context, assertion []byte) (EnrollmentClaims, error) {
	return f(ctx, assertion)
}

func (s *memoryCredentialStore) Protection() CredentialProtection { return s.protection }
func (s *memoryCredentialStore) Store(_ context.Context, _ string, value []byte) error {
	s.value = append([]byte(nil), value...)
	return nil
}
func (s *memoryCredentialStore) Load(context.Context, string) ([]byte, error) {
	if s.value == nil {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), s.value...), nil
}
func (s *memoryCredentialStore) Delete(context.Context, string) error {
	s.value = nil
	return nil
}

func TestDeviceIdentityUsesIndependentKeys(t *testing.T) {
	t.Parallel()

	identity, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	if err := identity.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if identity.DeviceID() == "" || identity.RecipientString() == "" {
		t.Fatal("generated identity has empty public fields")
	}
	message := []byte("domain-separated-message")
	signature, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ed25519.Verify(identity.SigningPublicKey(), message, signature) {
		t.Fatal("generated signature did not verify")
	}
	if bytes.Contains(identity.SigningPublicKey(), []byte(identity.RecipientString())) {
		t.Fatal("signing public key unexpectedly contains recipient text")
	}
}

func TestDeviceCredentialRequiresOSProtectionAndRoundTrips(t *testing.T) {
	t.Parallel()

	identity, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	insecure := &memoryCredentialStore{protection: "plaintext"}
	if err := SaveDeviceIdentity(context.Background(), insecure, identity); !errors.Is(err, ErrInsecureCredentialStore) {
		t.Fatalf("SaveDeviceIdentity(insecure) = %v, want ErrInsecureCredentialStore", err)
	}
	if _, err := LoadDeviceIdentity(context.Background(), insecure); !errors.Is(err, ErrInsecureCredentialStore) {
		t.Fatalf("LoadDeviceIdentity(insecure) = %v, want ErrInsecureCredentialStore", err)
	}

	store := &memoryCredentialStore{protection: CredentialProtectionOS}
	if err := SaveDeviceIdentity(context.Background(), store, identity); err != nil {
		t.Fatalf("SaveDeviceIdentity: %v", err)
	}
	loaded, err := LoadDeviceIdentity(context.Background(), store)
	if err != nil {
		t.Fatalf("LoadDeviceIdentity: %v", err)
	}
	if loaded.DeviceID() != identity.DeviceID() || loaded.RecipientString() != identity.RecipientString() ||
		!bytes.Equal(loaded.SigningPublicKey(), identity.SigningPublicKey()) {
		t.Fatal("credential round-trip changed public identity")
	}
	message := []byte("after-load")
	signature, err := loaded.Sign(message)
	if err != nil || !ed25519.Verify(identity.SigningPublicKey(), message, signature) {
		t.Fatalf("loaded signing key failed: %v", err)
	}

	store.value = append(store.value, 0x00)
	if _, err := LoadDeviceIdentity(context.Background(), store); !errors.Is(err, ErrInvalidDeviceCredential) {
		t.Fatalf("LoadDeviceIdentity(corrupt) = %v, want ErrInvalidDeviceCredential", err)
	}
	if err := DeleteDeviceIdentity(context.Background(), store); err != nil || store.value != nil {
		t.Fatalf("DeleteDeviceIdentity = %v, value remains %v", err, store.value != nil)
	}
}

func TestVerifyEnrollmentProducesDefensiveTypeState(t *testing.T) {
	t.Parallel()

	identity, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	assertion := []byte("signed-enrollment-assertion")
	verifier := enrollmentMapVerifier{string(assertion): {
		DeviceID:         identity.DeviceID(),
		Subject:          "github:user:12345",
		X25519Recipient:  identity.RecipientString(),
		Ed25519PublicKey: identity.SigningPublicKey(),
	}}
	verified, err := VerifyEnrollment(context.Background(), verifier, assertion)
	if err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
	assertion[0] = 'X'
	publicKey := verified.SigningPublicKey()
	publicKey[0] ^= 0xff
	if err := verified.validate(); err != nil {
		t.Fatalf("caller mutations affected VerifiedDevice: %v", err)
	}

	bad := enrollmentMapVerifier{"bad": {
		DeviceID:         identity.DeviceID(),
		Subject:          "github:user:12345",
		X25519Recipient:  "AGE1INVALID",
		Ed25519PublicKey: identity.SigningPublicKey(),
	}}
	if _, err := VerifyEnrollment(context.Background(), bad, []byte("bad")); !errors.Is(err, ErrInvalidEnrollment) {
		t.Fatalf("VerifyEnrollment(bad recipient) = %v, want ErrInvalidEnrollment", err)
	}
}

func TestVerifyEnrollmentSnapshotsAssertionBeforeVerification(t *testing.T) {
	t.Parallel()

	identity, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	assertion := []byte("signed-enrollment-assertion")
	want := append([]byte(nil), assertion...)
	verifier := enrollmentVerifierFunc(func(context.Context, []byte) (EnrollmentClaims, error) {
		assertion[0] = 'X'
		return EnrollmentClaims{
			DeviceID:         identity.DeviceID(),
			Subject:          "github:user:12345",
			X25519Recipient:  identity.RecipientString(),
			Ed25519PublicKey: identity.SigningPublicKey(),
		}, nil
	})
	verified, err := VerifyEnrollment(context.Background(), verifier, assertion)
	if err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
	if !bytes.Equal(verified.assertion, want) {
		t.Fatalf("verified assertion = %q, want immutable snapshot %q", verified.assertion, want)
	}
	if err := verified.validate(); err != nil {
		t.Fatalf("snapshot validation: %v", err)
	}
}

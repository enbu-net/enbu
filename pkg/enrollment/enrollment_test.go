package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
)

func TestSignedAssertionRoundTripAndDeviceBinding(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority("identity.enbu.example", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Sign(Claims{
		Issuer:           authority.Issuer,
		DeviceID:         device.DeviceID(),
		Subject:          "github.com:id:12345",
		X25519Recipient:  device.RecipientString(),
		Ed25519PublicKey: device.SigningPublicKey(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier([]Authority{authority})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifact.VerifyEnrollment(context.Background(), verifier, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if verified.DeviceID() != device.DeviceID() || verified.Subject() != "github.com:id:12345" || verified.RecipientString() != device.RecipientString() {
		t.Fatal("verified enrollment changed")
	}
}

func TestAssertionRejectsTamperingUnknownIssuerAndNonCanonicalInput(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority("identity.enbu.example", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Sign(Claims{
		Issuer:           authority.Issuer,
		DeviceID:         device.DeviceID(),
		Subject:          "github.com:id:12345",
		X25519Recipient:  device.RecipientString(),
		Ed25519PublicKey: device.SigningPublicKey(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier([]Authority{authority})
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-1] ^= 1
	if _, err := verifier.VerifyEnrollment(context.Background(), tampered); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("tamper error = %v", err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherAuthority, err := NewAuthority("other.enbu.example", otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	otherVerifier, err := NewVerifier([]Authority{otherAuthority})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherVerifier.VerifyEnrollment(context.Background(), encoded); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("unknown issuer error = %v", err)
	}
	if _, err := verifier.VerifyEnrollment(context.Background(), append(encoded, 0)); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("non-canonical error = %v", err)
	}
}

func TestVerifierPreservesCancellation(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority("identity.enbu.example", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier([]Authority{authority})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := verifier.VerifyEnrollment(ctx, []byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestSignWithDeviceCapabilityBootstrapsTrustedAuthority(t *testing.T) {
	t.Parallel()

	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority("device.enbu.test", device.SigningPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := SignWithSigner(Claims{
		Issuer:           "device.enbu.test",
		DeviceID:         device.DeviceID(),
		Subject:          "github:12345",
		X25519Recipient:  device.RecipientString(),
		Ed25519PublicKey: device.SigningPublicKey(),
	}, device)
	if err != nil {
		t.Fatalf("SignWithSigner: %v", err)
	}
	verifier, err := NewVerifier([]Authority{authority})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifact.VerifyEnrollment(context.Background(), verifier, assertion)
	if err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
	if verified.DeviceID() != device.DeviceID() || verified.Subject() != "github:12345" {
		t.Fatalf("verified device = %s/%s", verified.DeviceID(), verified.Subject())
	}
}

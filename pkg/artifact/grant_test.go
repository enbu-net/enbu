package artifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sort"
	"testing"

	"github.com/opencontainers/go-digest"
)

type enrollmentMapVerifier map[string]EnrollmentClaims

func (v enrollmentMapVerifier) VerifyEnrollment(_ context.Context, assertion []byte) (EnrollmentClaims, error) {
	claims, ok := v[string(assertion)]
	if !ok {
		return EnrollmentClaims{}, errors.New("unknown assertion")
	}
	claims.Ed25519PublicKey = append(ed25519.PublicKey(nil), claims.Ed25519PublicKey...)
	return claims, nil
}

type grantDeviceFixture struct {
	identity  *DeviceIdentity
	verified  VerifiedDevice
	assertion []byte
}

func newGrantDevice(t *testing.T, verifier enrollmentMapVerifier, subject string) grantDeviceFixture {
	t.Helper()
	identity, err := GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	assertion := []byte("enrollment:" + string(identity.DeviceID()))
	verifier[string(assertion)] = EnrollmentClaims{
		DeviceID:         identity.DeviceID(),
		Subject:          subject,
		X25519Recipient:  identity.RecipientString(),
		Ed25519PublicKey: identity.SigningPublicKey(),
	}
	verified, err := VerifyEnrollment(context.Background(), verifier, assertion)
	if err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
	return grantDeviceFixture{identity: identity, verified: verified, assertion: assertion}
}

func TestAccessGrantRoundTripAndPublicAnonymity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	verifier := enrollmentMapVerifier{}
	alice := newGrantDevice(t, verifier, "github:user:1001")
	bob := newGrantDevice(t, verifier, "github:user:1002")
	outsider := newGrantDevice(t, verifier, "github:user:1003")
	materialIdentity, err := GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	material := digest.FromString("material-manifest")
	policy := digest.FromString("policy-revision")
	grant, err := CreateAccessGrant(ctx, material, policy, materialIdentity, alice.identity, []VerifiedDevice{bob.verified, alice.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}
	encoded, err := EncodeAccessGrant(grant)
	if err != nil {
		t.Fatalf("EncodeAccessGrant: %v", err)
	}
	decoded, err := DecodeAccessGrant(encoded)
	if err != nil {
		t.Fatalf("DecodeAccessGrant: %v", err)
	}
	if decoded.Material != material || len(decoded.Wraps) != 2 {
		t.Fatalf("decoded Grant = %#v", decoded)
	}

	for _, device := range []grantDeviceFixture{alice, bob} {
		opened, err := OpenAccessGrant(ctx, encoded, device.identity, verifier)
		if err != nil {
			t.Fatalf("OpenAccessGrant(%s): %v", device.identity.DeviceID(), err)
		}
		if opened.Identity.RecipientString() != materialIdentity.RecipientString() || opened.Claims.Policy != policy {
			t.Fatal("opened Grant changed material identity or policy")
		}
	}
	if _, err := OpenAccessGrant(ctx, encoded, outsider.identity, verifier); !errors.Is(err, ErrGrantAccessDenied) {
		t.Fatalf("OpenAccessGrant(outsider) = %v, want ErrGrantAccessDenied", err)
	}

	for name, secret := range map[string][]byte{
		"alice device ID":  []byte(alice.identity.DeviceID()),
		"bob device ID":    []byte(bob.identity.DeviceID()),
		"alice recipient":  []byte(alice.identity.RecipientString()),
		"bob recipient":    []byte(bob.identity.RecipientString()),
		"alice subject":    []byte(alice.verified.Subject()),
		"bob subject":      []byte(bob.verified.Subject()),
		"alice enrollment": alice.assertion,
	} {
		if bytes.Contains(encoded, secret) {
			t.Errorf("public Grant leaks %s", name)
		}
	}

	ids := []string{string(decodedGrantRecipientID(t, encoded, alice.identity, verifier, 0)), string(decodedGrantRecipientID(t, encoded, alice.identity, verifier, 1))}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("recipient claims are not canonical: %v", ids)
	}
}

func decodedGrantRecipientID(t *testing.T, encoded []byte, device *DeviceIdentity, verifier EnrollmentVerifier, index int) UUID {
	t.Helper()
	opened, err := OpenAccessGrant(context.Background(), encoded, device, verifier)
	if err != nil {
		t.Fatalf("OpenAccessGrant: %v", err)
	}
	return opened.Claims.Recipients[index].DeviceID
}

func TestAccessGrantRewrapDoesNotRevokeRetainedMaterialIdentity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	verifier := enrollmentMapVerifier{}
	alice := newGrantDevice(t, verifier, "github:user:2001")
	bob := newGrantDevice(t, verifier, "github:user:2002")
	identity, err := GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	material := digest.FromString("unchanged-ciphertext-manifest")
	policy := digest.FromString("policy")
	oldGrant, err := CreateAccessGrant(ctx, material, policy, identity, alice.identity, []VerifiedDevice{alice.verified, bob.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant(old): %v", err)
	}
	newGrant, err := CreateAccessGrant(ctx, material, policy, identity, alice.identity, []VerifiedDevice{alice.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant(new): %v", err)
	}
	if oldGrant.Material != newGrant.Material || oldGrant.Material != material {
		t.Fatal("rewrap changed the material reference")
	}
	oldBytes, _ := EncodeAccessGrant(oldGrant)
	newBytes, _ := EncodeAccessGrant(newGrant)
	if bytes.Equal(oldBytes, newBytes) {
		t.Fatal("recipient change did not rewrite Grant")
	}
	oldOpened, err := OpenAccessGrant(ctx, oldBytes, bob.identity, verifier)
	if err != nil {
		t.Fatalf("removed device lost historical Grant: %v", err)
	}
	if _, err := OpenAccessGrant(ctx, newBytes, bob.identity, verifier); !errors.Is(err, ErrGrantAccessDenied) {
		t.Fatalf("removed device opened new Grant: %v", err)
	}
	retainedIdentity, err := oldOpened.Identity.identity()
	if err != nil {
		t.Fatalf("retained material identity: %v", err)
	}
	newBody, err := decryptGrantBytes(ctx, newGrant.BodyCiphertext, retainedIdentity, MaxGrantBodyBytes)
	if err != nil {
		t.Fatalf("retained identity no longer decrypts same-identity Grant: %v", err)
	}
	defer clearBytes(newBody)
	if digest.FromBytes(newBody) != newGrant.BodyDigest {
		t.Fatal("retained identity decrypted an unexpected Grant body")
	}
}

func TestAccessGrantRejectsTamperingAndSubstitution(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	verifier := enrollmentMapVerifier{}
	alice := newGrantDevice(t, verifier, "github:user:3001")
	bob := newGrantDevice(t, verifier, "github:user:3002")
	identity, err := GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	material := digest.FromString("material")
	first, err := CreateAccessGrant(ctx, material, digest.FromString("policy-one"), identity, alice.identity, []VerifiedDevice{alice.verified, bob.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant(first): %v", err)
	}
	second, err := CreateAccessGrant(ctx, material, digest.FromString("policy-two"), identity, alice.identity, []VerifiedDevice{alice.verified, bob.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant(second): %v", err)
	}

	tamperedBody := first
	tamperedBody.BodyCiphertext = append([]byte(nil), first.BodyCiphertext...)
	tamperedBody.BodyCiphertext[len(tamperedBody.BodyCiphertext)-1] ^= 0x01
	tamperedBytes, err := EncodeAccessGrant(tamperedBody)
	if err != nil {
		t.Fatalf("EncodeAccessGrant(tampered body): %v", err)
	}
	if _, err := OpenAccessGrant(ctx, tamperedBytes, alice.identity, verifier); !errors.Is(err, ErrInvalidAccessGrant) {
		t.Fatalf("OpenAccessGrant(tampered body) = %v, want ErrInvalidAccessGrant", err)
	}

	substituted := first
	substituted.BodyCiphertext = append([]byte(nil), second.BodyCiphertext...)
	substituted.BodyDigest = second.BodyDigest
	substitutedBytes, err := EncodeAccessGrant(substituted)
	if err != nil {
		t.Fatalf("EncodeAccessGrant(substituted): %v", err)
	}
	if _, err := OpenAccessGrant(ctx, substitutedBytes, alice.identity, verifier); !errors.Is(err, ErrInvalidAccessGrant) {
		t.Fatalf("OpenAccessGrant(substituted) = %v, want ErrInvalidAccessGrant", err)
	}

	tamperedWrap := first
	tamperedWrap.Wraps = append([]IdentityWrap(nil), first.Wraps...)
	tamperedWrap.Wraps[0].Ciphertext = append([]byte(nil), first.Wraps[0].Ciphertext...)
	tamperedWrap.Wraps[0].Ciphertext[0] ^= 0x01
	if _, err := EncodeAccessGrant(tamperedWrap); !errors.Is(err, ErrInvalidAccessGrant) {
		t.Fatalf("EncodeAccessGrant(tampered wrap) = %v, want ErrInvalidAccessGrant", err)
	}
}

func TestAccessGrantVerifiesSignatureAndHistoricalEnrollment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	verifier := enrollmentMapVerifier{}
	alice := newGrantDevice(t, verifier, "github:user:4001")
	identity, err := GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	grant, err := CreateAccessGrant(ctx, digest.FromString("material"), digest.FromString("policy"), identity, alice.identity, []VerifiedDevice{alice.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}

	materialAgeIdentity, err := identity.identity()
	if err != nil {
		t.Fatalf("material identity: %v", err)
	}
	body, err := decryptGrantBytes(ctx, grant.BodyCiphertext, materialAgeIdentity, MaxGrantBodyBytes)
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	var signed signedGrantClaims
	if err := UnmarshalStrict(body, &signed); err != nil {
		t.Fatalf("decode signed claims: %v", err)
	}
	signed.Signature[0] ^= 0x01
	badBody, err := MarshalCanonical(signed)
	if err != nil {
		t.Fatalf("encode bad claims: %v", err)
	}
	grant.BodyDigest = digest.FromBytes(badBody)
	materialRecipient, _ := identity.recipient()
	grant.BodyCiphertext, err = encryptGrantBytes(ctx, badBody, materialRecipient)
	if err != nil {
		t.Fatalf("encrypt bad claims: %v", err)
	}
	encoded, err := EncodeAccessGrant(grant)
	if err != nil {
		t.Fatalf("EncodeAccessGrant: %v", err)
	}
	if _, err := OpenAccessGrant(ctx, encoded, alice.identity, verifier); !errors.Is(err, ErrDeviceSignature) {
		t.Fatalf("OpenAccessGrant(bad signature) = %v, want ErrDeviceSignature", err)
	}

	verifier[string(alice.assertion)] = EnrollmentClaims{
		DeviceID:         alice.identity.DeviceID(),
		Subject:          "github:user:attacker",
		X25519Recipient:  alice.identity.RecipientString(),
		Ed25519PublicKey: alice.identity.SigningPublicKey(),
	}
	validGrant, err := CreateAccessGrant(ctx, digest.FromString("other-material"), digest.FromString("policy"), identity, alice.identity, []VerifiedDevice{alice.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant(valid enrollment snapshot): %v", err)
	}
	validBytes, _ := EncodeAccessGrant(validGrant)
	if _, err := OpenAccessGrant(ctx, validBytes, alice.identity, verifier); !errors.Is(err, ErrInvalidAccessGrant) {
		t.Fatalf("OpenAccessGrant(enrollment mismatch) = %v, want ErrInvalidAccessGrant", err)
	}
}

func TestCreateAccessGrantRejectsIssuerAndRecipientAmbiguity(t *testing.T) {
	t.Parallel()

	verifier := enrollmentMapVerifier{}
	alice := newGrantDevice(t, verifier, "github:user:5001")
	bob := newGrantDevice(t, verifier, "github:user:5002")
	identity, err := GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	material := digest.FromString("material")
	policy := digest.FromString("policy")
	if _, err := CreateAccessGrant(context.Background(), material, policy, identity, alice.identity, []VerifiedDevice{bob.verified}); !errors.Is(err, ErrInvalidAccessGrant) {
		t.Fatalf("missing issuer = %v, want ErrInvalidAccessGrant", err)
	}
	if _, err := CreateAccessGrant(context.Background(), material, policy, identity, alice.identity, []VerifiedDevice{alice.verified, alice.verified}); !errors.Is(err, ErrInvalidAccessGrant) {
		t.Fatalf("duplicate recipient = %v, want ErrInvalidAccessGrant", err)
	}
}

func TestOpenAccessGrantPreservesCancellation(t *testing.T) {
	t.Parallel()

	verifier := enrollmentMapVerifier{}
	alice := newGrantDevice(t, verifier, "github:user:6001")
	identity, err := GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	grant, err := CreateAccessGrant(context.Background(), digest.FromString("material"), digest.FromString("policy"), identity, alice.identity, []VerifiedDevice{alice.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}
	encoded, err := EncodeAccessGrant(grant)
	if err != nil {
		t.Fatalf("EncodeAccessGrant: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OpenAccessGrant(canceled, encoded, alice.identity, verifier); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenAccessGrant(pre-canceled) = %v, want context.Canceled", err)
	}

	ctx, cancelDuringVerification := context.WithCancel(context.Background())
	cancelingVerifier := enrollmentVerifierFunc(func(ctx context.Context, _ []byte) (EnrollmentClaims, error) {
		cancelDuringVerification()
		return EnrollmentClaims{}, ctx.Err()
	})
	if _, err := OpenAccessGrant(ctx, encoded, alice.identity, cancelingVerifier); !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenAccessGrant(canceled verifier) = %v, want context.Canceled", err)
	}
}

func TestOpenAccessGrantRejectsBadSignatureBeforeOtherEnrollments(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	verifier := enrollmentMapVerifier{}
	alice := newGrantDevice(t, verifier, "github:user:7001")
	bob := newGrantDevice(t, verifier, "github:user:7002")
	carol := newGrantDevice(t, verifier, "github:user:7003")
	identity, err := GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	grant, err := CreateAccessGrant(ctx, digest.FromString("material"), digest.FromString("policy"), identity, alice.identity, []VerifiedDevice{alice.verified, bob.verified, carol.verified})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}
	materialAgeIdentity, _ := identity.identity()
	body, err := decryptGrantBytes(ctx, grant.BodyCiphertext, materialAgeIdentity, MaxGrantBodyBytes)
	if err != nil {
		t.Fatalf("decrypt Grant body: %v", err)
	}
	var signed signedGrantClaims
	if err := UnmarshalStrict(body, &signed); err != nil {
		t.Fatalf("decode signed claims: %v", err)
	}
	signed.Signature[0] ^= 0x01
	tamperedBody, err := MarshalCanonical(signed)
	if err != nil {
		t.Fatalf("encode tampered claims: %v", err)
	}
	grant.BodyDigest = digest.FromBytes(tamperedBody)
	materialRecipient, _ := identity.recipient()
	grant.BodyCiphertext, err = encryptGrantBytes(ctx, tamperedBody, materialRecipient)
	if err != nil {
		t.Fatalf("encrypt tampered claims: %v", err)
	}
	encoded, err := EncodeAccessGrant(grant)
	if err != nil {
		t.Fatalf("EncodeAccessGrant: %v", err)
	}

	verificationCalls := 0
	countingVerifier := enrollmentVerifierFunc(func(_ context.Context, assertion []byte) (EnrollmentClaims, error) {
		verificationCalls++
		return verifier.VerifyEnrollment(ctx, assertion)
	})
	if _, err := OpenAccessGrant(ctx, encoded, alice.identity, countingVerifier); !errors.Is(err, ErrDeviceSignature) {
		t.Fatalf("OpenAccessGrant(bad signature) = %v, want ErrDeviceSignature", err)
	}
	if verificationCalls != 1 {
		t.Fatalf("enrollment verifier called %d times before signature rejection, want 1", verificationCalls)
	}
}

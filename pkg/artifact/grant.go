package artifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sort"

	"filippo.io/age"
	"github.com/opencontainers/go-digest"
)

const (
	AccessGrantAPIVersion = "artifacts.enbu.net/v1alpha1"
	AccessGrantKind       = "AccessGrant"

	MaxGrantBytes      = 16 * 1024 * 1024
	MaxGrantBodyBytes  = 15 * 1024 * 1024
	MaxGrantWrapBytes  = 4 * 1024
	MaxGrantRecipients = 4 * 1024

	grantClaimsKind          = "AccessGrantClaims"
	materialIdentityWrapKind = "MaterialIdentityWrap"
	grantSignatureDomain     = "enbu.net/access-grant/v1\x00"
)

var (
	ErrInvalidAccessGrant = errors.New("invalid access grant")
	ErrGrantAccessDenied  = errors.New("access grant cannot be opened by this device")
)

// AccessGrant is the public encrypted envelope. Recipient identifiers and
// enrollment assertions exist only inside BodyCiphertext.
type AccessGrant struct {
	APIVersion     string         `cbor:"apiVersion" json:"apiVersion"`
	Kind           string         `cbor:"kind" json:"kind"`
	Material       digest.Digest  `cbor:"material" json:"material"`
	BodyDigest     digest.Digest  `cbor:"bodyDigest" json:"bodyDigest"`
	BodyCiphertext []byte         `cbor:"bodyCiphertext" json:"bodyCiphertext"`
	Wraps          []IdentityWrap `cbor:"wraps" json:"wraps"`
}

type IdentityWrap struct {
	Digest     digest.Digest `cbor:"digest" json:"digest"`
	Ciphertext []byte        `cbor:"ciphertext" json:"ciphertext"`
}

// GrantClaims are visible only after a device unwraps the material identity.
// The signature proves integrity; PR4 policy approval and a verified Commit
// remain required before a Grant is authoritative.
type GrantClaims struct {
	APIVersion string           `cbor:"apiVersion" json:"apiVersion"`
	Kind       string           `cbor:"kind" json:"kind"`
	Material   digest.Digest    `cbor:"material" json:"material"`
	Policy     digest.Digest    `cbor:"policy" json:"policy"`
	Issuer     UUID             `cbor:"issuer" json:"issuer"`
	Recipients []GrantRecipient `cbor:"recipients" json:"recipients"`
}

type GrantRecipient struct {
	DeviceID         UUID              `cbor:"deviceID" json:"deviceID"`
	Subject          string            `cbor:"subject" json:"subject"`
	X25519Recipient  string            `cbor:"x25519Recipient" json:"x25519Recipient"`
	Ed25519PublicKey ed25519.PublicKey `cbor:"ed25519PublicKey" json:"ed25519PublicKey"`
	EnrollmentDigest digest.Digest     `cbor:"enrollmentDigest" json:"enrollmentDigest"`
	Enrollment       []byte            `cbor:"enrollment" json:"enrollment"`
	WrapDigest       digest.Digest     `cbor:"wrapDigest" json:"wrapDigest"`
}

type signedGrantClaims struct {
	Claims    GrantClaims `cbor:"claims"`
	Signature []byte      `cbor:"signature"`
}

type materialIdentityWrap struct {
	APIVersion string        `cbor:"apiVersion"`
	Kind       string        `cbor:"kind"`
	Material   digest.Digest `cbor:"material"`
	Identity   string        `cbor:"identity"`
}

type OpenedGrant struct {
	Claims   GrantClaims
	Identity MaterialIdentity
}

func CreateAccessGrant(
	ctx context.Context,
	material digest.Digest,
	policy digest.Digest,
	identity MaterialIdentity,
	issuer *DeviceIdentity,
	recipients []VerifiedDevice,
) (AccessGrant, error) {
	if err := ctx.Err(); err != nil {
		return AccessGrant{}, err
	}
	if err := validateDigest(material); err != nil {
		return AccessGrant{}, fmt.Errorf("%w: material digest: %v", ErrInvalidAccessGrant, err)
	}
	if err := validateDigest(policy); err != nil {
		return AccessGrant{}, fmt.Errorf("%w: policy digest: %v", ErrInvalidAccessGrant, err)
	}
	if err := issuer.validate(); err != nil {
		return AccessGrant{}, err
	}
	if len(recipients) == 0 || len(recipients) > MaxGrantRecipients {
		return AccessGrant{}, fmt.Errorf("%w: recipient count", ErrInvalidAccessGrant)
	}
	identitySecret, err := identity.marshalSecret()
	if err != nil {
		return AccessGrant{}, err
	}

	claims := GrantClaims{
		APIVersion: AccessGrantAPIVersion,
		Kind:       grantClaimsKind,
		Material:   material,
		Policy:     policy,
		Issuer:     issuer.DeviceID(),
		Recipients: make([]GrantRecipient, 0, len(recipients)),
	}
	grant := AccessGrant{
		APIVersion: AccessGrantAPIVersion,
		Kind:       AccessGrantKind,
		Material:   material,
		Wraps:      make([]IdentityWrap, 0, len(recipients)),
	}

	issuerFound := false
	for i, recipient := range recipients {
		if err := ctx.Err(); err != nil {
			return AccessGrant{}, err
		}
		if err := recipient.validate(); err != nil {
			return AccessGrant{}, fmt.Errorf("%w: recipients[%d]: %v", ErrInvalidAccessGrant, i, err)
		}
		wrapPlaintext, err := MarshalCanonical(materialIdentityWrap{
			APIVersion: AccessGrantAPIVersion,
			Kind:       materialIdentityWrapKind,
			Material:   material,
			Identity:   identitySecret,
		})
		if err != nil {
			return AccessGrant{}, fmt.Errorf("encode identity wrap: %w", err)
		}
		wrapCiphertext, err := encryptGrantBytes(ctx, wrapPlaintext, recipient.recipient)
		clearBytes(wrapPlaintext)
		if err != nil {
			return AccessGrant{}, fmt.Errorf("encrypt identity wrap: %w", err)
		}
		if len(wrapCiphertext) > MaxGrantWrapBytes {
			return AccessGrant{}, fmt.Errorf("%w: encrypted identity wrap exceeds limit", ErrInvalidAccessGrant)
		}
		wrapDigest := digest.FromBytes(wrapCiphertext)
		grant.Wraps = append(grant.Wraps, IdentityWrap{Digest: wrapDigest, Ciphertext: wrapCiphertext})
		claims.Recipients = append(claims.Recipients, GrantRecipient{
			DeviceID:         recipient.id,
			Subject:          recipient.subject,
			X25519Recipient:  recipient.recipient.String(),
			Ed25519PublicKey: append(ed25519.PublicKey(nil), recipient.signingKey...),
			EnrollmentDigest: recipient.assertionDigest,
			Enrollment:       append([]byte(nil), recipient.assertion...),
			WrapDigest:       wrapDigest,
		})
		if recipientMatchesIdentity(recipient, issuer) {
			issuerFound = true
		}
	}
	if !issuerFound {
		return AccessGrant{}, fmt.Errorf("%w: issuer is not an exactly matching verified recipient", ErrInvalidAccessGrant)
	}

	claims = canonicalGrantClaims(claims)
	signedClaims, err := signGrantClaims(claims, issuer)
	if err != nil {
		return AccessGrant{}, err
	}
	if len(signedClaims) > MaxGrantBodyBytes {
		clearBytes(signedClaims)
		return AccessGrant{}, fmt.Errorf("%w: signed claims exceed limit", ErrInvalidAccessGrant)
	}
	grant.BodyDigest = digest.FromBytes(signedClaims)
	materialRecipient, err := identity.recipient()
	if err != nil {
		return AccessGrant{}, err
	}
	grant.BodyCiphertext, err = encryptGrantBytes(ctx, signedClaims, materialRecipient)
	clearBytes(signedClaims)
	if err != nil {
		return AccessGrant{}, fmt.Errorf("encrypt grant body: %w", err)
	}
	sort.Slice(grant.Wraps, func(i, j int) bool { return grant.Wraps[i].Digest < grant.Wraps[j].Digest })
	if err := grant.Validate(); err != nil {
		return AccessGrant{}, err
	}
	return grant, nil
}

func (g AccessGrant) Validate() error {
	if g.APIVersion != AccessGrantAPIVersion || g.Kind != AccessGrantKind {
		return fmt.Errorf("%w: unsupported envelope type", ErrInvalidAccessGrant)
	}
	if err := validateDigest(g.Material); err != nil {
		return fmt.Errorf("%w: material digest: %v", ErrInvalidAccessGrant, err)
	}
	if err := validateDigest(g.BodyDigest); err != nil {
		return fmt.Errorf("%w: body digest: %v", ErrInvalidAccessGrant, err)
	}
	if len(g.BodyCiphertext) == 0 || len(g.BodyCiphertext) > MaxGrantBodyBytes {
		return fmt.Errorf("%w: encrypted body size", ErrInvalidAccessGrant)
	}
	if len(g.Wraps) == 0 || len(g.Wraps) > MaxGrantRecipients {
		return fmt.Errorf("%w: identity wrap count", ErrInvalidAccessGrant)
	}
	seen := make(map[digest.Digest]struct{}, len(g.Wraps))
	for i, wrap := range g.Wraps {
		if err := validateDigest(wrap.Digest); err != nil {
			return fmt.Errorf("%w: wraps[%d] digest: %v", ErrInvalidAccessGrant, i, err)
		}
		if len(wrap.Ciphertext) == 0 || len(wrap.Ciphertext) > MaxGrantWrapBytes {
			return fmt.Errorf("%w: wraps[%d] ciphertext size", ErrInvalidAccessGrant, i)
		}
		if digest.FromBytes(wrap.Ciphertext) != wrap.Digest {
			return fmt.Errorf("%w: wraps[%d] digest mismatch", ErrInvalidAccessGrant, i)
		}
		if _, exists := seen[wrap.Digest]; exists {
			return fmt.Errorf("%w: duplicate identity wrap", ErrInvalidAccessGrant)
		}
		seen[wrap.Digest] = struct{}{}
	}
	return nil
}

func EncodeAccessGrant(grant AccessGrant) ([]byte, error) {
	if err := grant.Validate(); err != nil {
		return nil, err
	}
	canonical := grant
	canonical.BodyCiphertext = append([]byte(nil), grant.BodyCiphertext...)
	canonical.Wraps = append([]IdentityWrap(nil), grant.Wraps...)
	sort.Slice(canonical.Wraps, func(i, j int) bool { return canonical.Wraps[i].Digest < canonical.Wraps[j].Digest })
	data, err := MarshalCanonical(canonical)
	if err != nil {
		return nil, fmt.Errorf("encode access grant: %w", err)
	}
	if len(data) > MaxGrantBytes {
		return nil, fmt.Errorf("%w: encoded Grant exceeds limit", ErrInvalidAccessGrant)
	}
	return data, nil
}

func DecodeAccessGrant(data []byte) (AccessGrant, error) {
	if len(data) == 0 || len(data) > MaxGrantBytes {
		return AccessGrant{}, fmt.Errorf("%w: encoded Grant size", ErrInvalidAccessGrant)
	}
	var grant AccessGrant
	if err := UnmarshalStrict(data, &grant); err != nil {
		return AccessGrant{}, fmt.Errorf("%w: %v", ErrInvalidAccessGrant, err)
	}
	canonical, err := EncodeAccessGrant(grant)
	if err != nil {
		return AccessGrant{}, err
	}
	if !bytes.Equal(data, canonical) {
		return AccessGrant{}, fmt.Errorf("%w: non-canonical encoding", ErrInvalidAccessGrant)
	}
	return grant, nil
}

func OpenAccessGrant(ctx context.Context, data []byte, device *DeviceIdentity, verifier EnrollmentVerifier) (OpenedGrant, error) {
	if err := ctx.Err(); err != nil {
		return OpenedGrant{}, err
	}
	grant, err := DecodeAccessGrant(data)
	if err != nil {
		return OpenedGrant{}, err
	}
	if err := ctx.Err(); err != nil {
		return OpenedGrant{}, err
	}
	if err := device.validate(); err != nil {
		return OpenedGrant{}, err
	}

	var (
		identity         MaterialIdentity
		openedWrapDigest digest.Digest
		opened           bool
	)
	for _, wrap := range grant.Wraps {
		if err := ctx.Err(); err != nil {
			return OpenedGrant{}, err
		}
		plaintext, decryptErr := decryptGrantBytes(ctx, wrap.Ciphertext, device.recipient, MaxGrantWrapBytes)
		if decryptErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return OpenedGrant{}, ctxErr
			}
			continue
		}
		var value materialIdentityWrap
		decodeErr := decodeCanonicalValue(plaintext, &value)
		clearBytes(plaintext)
		if decodeErr != nil || value.APIVersion != AccessGrantAPIVersion || value.Kind != materialIdentityWrapKind || value.Material != grant.Material {
			continue
		}
		identity, err = parseMaterialIdentity(value.Identity)
		if err != nil {
			continue
		}
		openedWrapDigest = wrap.Digest
		opened = true
		break
	}
	if !opened {
		return OpenedGrant{}, ErrGrantAccessDenied
	}

	materialIdentity, err := identity.identity()
	if err != nil {
		return OpenedGrant{}, ErrGrantAccessDenied
	}
	body, err := decryptGrantBytes(ctx, grant.BodyCiphertext, materialIdentity, MaxGrantBodyBytes)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return OpenedGrant{}, ctxErr
		}
		return OpenedGrant{}, fmt.Errorf("%w: encrypted body authentication failed", ErrInvalidAccessGrant)
	}
	defer clearBytes(body)
	if digest.FromBytes(body) != grant.BodyDigest {
		return OpenedGrant{}, fmt.Errorf("%w: body digest mismatch", ErrInvalidAccessGrant)
	}
	signed, unsigned, err := decodeSignedGrantClaims(body)
	if err != nil {
		return OpenedGrant{}, err
	}
	if signed.Claims.Material != grant.Material {
		return OpenedGrant{}, fmt.Errorf("%w: material substitution", ErrInvalidAccessGrant)
	}

	claimWraps := make(map[digest.Digest]struct{}, len(signed.Claims.Recipients))
	var (
		issuerClaims  *GrantRecipient
		openerMatched bool
	)
	deviceSigningKey := device.SigningPublicKey()
	for i := range signed.Claims.Recipients {
		recipient := &signed.Claims.Recipients[i]
		claimWraps[recipient.WrapDigest] = struct{}{}
		if recipient.DeviceID == signed.Claims.Issuer {
			issuerClaims = recipient
		}
		if recipient.DeviceID == device.DeviceID() &&
			recipient.WrapDigest == openedWrapDigest &&
			recipient.X25519Recipient == device.RecipientString() &&
			bytes.Equal(recipient.Ed25519PublicKey, deviceSigningKey) {
			openerMatched = true
		}
	}
	if len(claimWraps) != len(grant.Wraps) {
		return OpenedGrant{}, fmt.Errorf("%w: wrap set mismatch", ErrInvalidAccessGrant)
	}
	for _, wrap := range grant.Wraps {
		if _, exists := claimWraps[wrap.Digest]; !exists {
			return OpenedGrant{}, fmt.Errorf("%w: unsigned identity wrap", ErrInvalidAccessGrant)
		}
	}
	if !openerMatched {
		return OpenedGrant{}, ErrGrantAccessDenied
	}
	if issuerClaims == nil {
		return OpenedGrant{}, fmt.Errorf("%w: missing issuer claims", ErrInvalidAccessGrant)
	}
	issuer, err := VerifyEnrollment(ctx, verifier, issuerClaims.Enrollment)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return OpenedGrant{}, ctxErr
		}
		return OpenedGrant{}, fmt.Errorf("%w: issuer enrollment", ErrInvalidAccessGrant)
	}
	if !recipientMatchesClaims(issuer, *issuerClaims) {
		return OpenedGrant{}, fmt.Errorf("%w: issuer enrollment binding mismatch", ErrInvalidAccessGrant)
	}
	if !ed25519.Verify(issuer.signingKey, grantSigningMessage(unsigned), signed.Signature) {
		return OpenedGrant{}, ErrDeviceSignature
	}

	for i, recipient := range signed.Claims.Recipients {
		if recipient.DeviceID == signed.Claims.Issuer {
			continue
		}
		candidate, err := VerifyEnrollment(ctx, verifier, recipient.Enrollment)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return OpenedGrant{}, ctxErr
			}
			return OpenedGrant{}, fmt.Errorf("%w: recipient enrollment %d", ErrInvalidAccessGrant, i)
		}
		if !recipientMatchesClaims(candidate, recipient) {
			return OpenedGrant{}, fmt.Errorf("%w: enrollment binding mismatch", ErrInvalidAccessGrant)
		}
	}
	return OpenedGrant{Claims: signed.Claims, Identity: identity}, nil
}

func (c GrantClaims) Validate() error {
	if c.APIVersion != AccessGrantAPIVersion || c.Kind != grantClaimsKind {
		return fmt.Errorf("%w: unsupported claims type", ErrInvalidAccessGrant)
	}
	if err := validateDigest(c.Material); err != nil {
		return fmt.Errorf("%w: claims material: %v", ErrInvalidAccessGrant, err)
	}
	if err := validateDigest(c.Policy); err != nil {
		return fmt.Errorf("%w: claims policy: %v", ErrInvalidAccessGrant, err)
	}
	if err := c.Issuer.Validate(); err != nil {
		return fmt.Errorf("%w: issuer: %v", ErrInvalidAccessGrant, err)
	}
	if len(c.Recipients) == 0 || len(c.Recipients) > MaxGrantRecipients {
		return fmt.Errorf("%w: claims recipient count", ErrInvalidAccessGrant)
	}
	deviceIDs := make(map[UUID]struct{}, len(c.Recipients))
	recipients := make(map[string]struct{}, len(c.Recipients))
	signingKeys := make(map[string]struct{}, len(c.Recipients))
	wraps := make(map[digest.Digest]struct{}, len(c.Recipients))
	issuerFound := false
	for i, recipient := range c.Recipients {
		if err := recipient.Validate(); err != nil {
			return fmt.Errorf("%w: recipients[%d]: %v", ErrInvalidAccessGrant, i, err)
		}
		if _, exists := deviceIDs[recipient.DeviceID]; exists {
			return fmt.Errorf("%w: duplicate device ID", ErrInvalidAccessGrant)
		}
		if _, exists := recipients[recipient.X25519Recipient]; exists {
			return fmt.Errorf("%w: duplicate X25519 recipient", ErrInvalidAccessGrant)
		}
		signingKey := string(recipient.Ed25519PublicKey)
		if _, exists := signingKeys[signingKey]; exists {
			return fmt.Errorf("%w: duplicate Ed25519 public key", ErrInvalidAccessGrant)
		}
		if _, exists := wraps[recipient.WrapDigest]; exists {
			return fmt.Errorf("%w: duplicate wrap digest", ErrInvalidAccessGrant)
		}
		deviceIDs[recipient.DeviceID] = struct{}{}
		recipients[recipient.X25519Recipient] = struct{}{}
		signingKeys[signingKey] = struct{}{}
		wraps[recipient.WrapDigest] = struct{}{}
		issuerFound = issuerFound || recipient.DeviceID == c.Issuer
	}
	if !issuerFound {
		return fmt.Errorf("%w: issuer is not a recipient", ErrInvalidAccessGrant)
	}
	return nil
}

func (r GrantRecipient) Validate() error {
	if err := r.DeviceID.Validate(); err != nil {
		return fmt.Errorf("device ID: %w", err)
	}
	if err := validatePrincipal(r.Subject); err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	recipient, err := age.ParseX25519Recipient(r.X25519Recipient)
	if err != nil || recipient.String() != r.X25519Recipient {
		return errors.New("invalid canonical X25519 recipient")
	}
	if len(r.Ed25519PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	if len(r.Enrollment) == 0 || len(r.Enrollment) > MaxEnrollmentAssertionBytes {
		return errors.New("invalid enrollment assertion size")
	}
	if err := validateDigest(r.EnrollmentDigest); err != nil || digest.FromBytes(r.Enrollment) != r.EnrollmentDigest {
		return errors.New("enrollment digest mismatch")
	}
	if err := validateDigest(r.WrapDigest); err != nil {
		return fmt.Errorf("wrap digest: %w", err)
	}
	return nil
}

func signGrantClaims(claims GrantClaims, signer *DeviceIdentity) ([]byte, error) {
	if err := claims.Validate(); err != nil {
		return nil, err
	}
	unsigned, err := MarshalCanonical(canonicalGrantClaims(claims))
	if err != nil {
		return nil, fmt.Errorf("encode Grant claims: %w", err)
	}
	signature, err := signer.Sign(grantSigningMessage(unsigned))
	if err != nil {
		return nil, err
	}
	return MarshalCanonical(signedGrantClaims{Claims: canonicalGrantClaims(claims), Signature: signature})
}

func decodeSignedGrantClaims(data []byte) (signedGrantClaims, []byte, error) {
	var signed signedGrantClaims
	if err := UnmarshalStrict(data, &signed); err != nil {
		return signedGrantClaims{}, nil, fmt.Errorf("%w: signed claims: %v", ErrInvalidAccessGrant, err)
	}
	if len(signed.Signature) != ed25519.SignatureSize {
		return signedGrantClaims{}, nil, fmt.Errorf("%w: signature size", ErrInvalidAccessGrant)
	}
	if err := signed.Claims.Validate(); err != nil {
		return signedGrantClaims{}, nil, err
	}
	canonicalClaims := canonicalGrantClaims(signed.Claims)
	canonicalSigned, err := MarshalCanonical(signedGrantClaims{Claims: canonicalClaims, Signature: signed.Signature})
	if err != nil {
		return signedGrantClaims{}, nil, err
	}
	if !bytes.Equal(data, canonicalSigned) {
		return signedGrantClaims{}, nil, fmt.Errorf("%w: non-canonical signed claims", ErrInvalidAccessGrant)
	}
	signed.Claims = canonicalClaims
	unsigned, err := MarshalCanonical(canonicalClaims)
	if err != nil {
		return signedGrantClaims{}, nil, err
	}
	return signed, unsigned, nil
}

func decodeCanonicalValue(data []byte, destination any) error {
	if err := UnmarshalStrict(data, destination); err != nil {
		return err
	}
	canonical, err := MarshalCanonical(destination)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return ErrNonCanonicalEncoding
	}
	return nil
}

func canonicalGrantClaims(claims GrantClaims) GrantClaims {
	canonical := claims
	canonical.Recipients = append([]GrantRecipient(nil), claims.Recipients...)
	sort.Slice(canonical.Recipients, func(i, j int) bool {
		return canonical.Recipients[i].DeviceID < canonical.Recipients[j].DeviceID
	})
	return canonical
}

func recipientMatchesIdentity(recipient VerifiedDevice, identity *DeviceIdentity) bool {
	return recipient.id == identity.DeviceID() &&
		recipient.recipient.String() == identity.RecipientString() &&
		bytes.Equal(recipient.signingKey, identity.SigningPublicKey())
}

func recipientMatchesClaims(device VerifiedDevice, claims GrantRecipient) bool {
	return device.id == claims.DeviceID &&
		device.subject == claims.Subject &&
		device.recipient.String() == claims.X25519Recipient &&
		bytes.Equal(device.signingKey, claims.Ed25519PublicKey) &&
		device.assertionDigest == claims.EnrollmentDigest &&
		bytes.Equal(device.assertion, claims.Enrollment)
}

func grantSigningMessage(unsigned []byte) []byte {
	message := make([]byte, 0, len(grantSignatureDomain)+len(unsigned))
	message = append(message, grantSignatureDomain...)
	return append(message, unsigned...)
}

func encryptGrantBytes(ctx context.Context, plaintext []byte, recipient age.Recipient) ([]byte, error) {
	var destination bytes.Buffer
	writer, err := age.Encrypt(&destination, recipient)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, 32*1024)
	defer clearBytes(buffer)
	_, copyErr := copyBytesWithContext(ctx, writer, bytes.NewReader(plaintext), buffer)
	closeErr := writer.Close()
	if copyErr != nil || closeErr != nil {
		return nil, errors.Join(copyErr, closeErr)
	}
	return destination.Bytes(), nil
}

func decryptGrantBytes(ctx context.Context, ciphertext []byte, identity age.Identity, limit int64) ([]byte, error) {
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, err
	}
	var destination bytes.Buffer
	buffer := make([]byte, 32*1024)
	defer clearBytes(buffer)
	_, err = copyBytesWithContext(ctx, &destination, io.LimitReader(reader, limit+1), buffer)
	if err != nil {
		return nil, err
	}
	if int64(destination.Len()) > limit {
		return nil, errors.New("decrypted Grant value exceeds limit")
	}
	return destination.Bytes(), nil
}

func copyBytesWithContext(ctx context.Context, destination io.Writer, source io.Reader, buffer []byte) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
		if read == 0 {
			return total, io.ErrNoProgress
		}
	}
}

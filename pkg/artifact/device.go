package artifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/opencontainers/go-digest"
	"golang.org/x/text/unicode/norm"
)

const (
	MaxEnrollmentAssertionBytes = 64 * 1024
	MaxDeviceCredentialBytes    = 4 * 1024

	deviceCredentialAPIVersion = "credentials.enbu.net/v1alpha1"
	deviceCredentialKind       = "DeviceIdentity"
	deviceCredentialName       = "device-identity-v1"
)

var (
	ErrInvalidDeviceIdentity   = errors.New("invalid device identity")
	ErrInvalidEnrollment       = errors.New("invalid device enrollment")
	ErrInsecureCredentialStore = errors.New("credential store is not OS protected")
	ErrInvalidDeviceCredential = errors.New("invalid device credential")
	ErrDeviceSignature         = errors.New("invalid device signature")
)

// DeviceIdentity contains independent X25519 encryption and Ed25519 signing
// keys. Private key material is intentionally unavailable through accessors.
type DeviceIdentity struct {
	id         UUID
	recipient  *age.X25519Identity
	signingKey ed25519.PrivateKey
}

func GenerateDeviceIdentity() (*DeviceIdentity, error) {
	id, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("generate device ID: %w", err)
	}
	recipient, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate device recipient: %w", err)
	}
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device signing key: %w", err)
	}
	return &DeviceIdentity{id: id, recipient: recipient, signingKey: signingKey}, nil
}

func (d *DeviceIdentity) DeviceID() UUID {
	if d == nil {
		return ""
	}
	return d.id
}

func (d *DeviceIdentity) RecipientString() string {
	if d == nil || d.recipient == nil {
		return ""
	}
	return d.recipient.Recipient().String()
}

func (d *DeviceIdentity) SigningPublicKey() ed25519.PublicKey {
	if d == nil || len(d.signingKey) != ed25519.PrivateKeySize {
		return nil
	}
	publicKey := d.signingKey.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), publicKey...)
}

func (d *DeviceIdentity) Sign(message []byte) ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return ed25519.Sign(d.signingKey, message), nil
}

func (d *DeviceIdentity) validate() error {
	if d == nil {
		return fmt.Errorf("%w: nil identity", ErrInvalidDeviceIdentity)
	}
	if err := d.id.Validate(); err != nil {
		return fmt.Errorf("%w: device ID: %v", ErrInvalidDeviceIdentity, err)
	}
	if d.recipient == nil {
		return fmt.Errorf("%w: missing X25519 identity", ErrInvalidDeviceIdentity)
	}
	if len(d.signingKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: invalid Ed25519 private key", ErrInvalidDeviceIdentity)
	}
	return nil
}

func generateUUID() (UUID, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw)
	return ParseUUID(encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:])
}

// EnrollmentClaims are produced only by a trusted EnrollmentVerifier. Subject
// is a provider-qualified immutable principal, not a mutable username.
type EnrollmentClaims struct {
	DeviceID         UUID
	Subject          string
	X25519Recipient  string
	Ed25519PublicKey ed25519.PublicKey
}

type EnrollmentVerifier interface {
	VerifyEnrollment(context.Context, []byte) (EnrollmentClaims, error)
}

// VerifiedDevice is a type-state token proving an opaque enrollment assertion
// was checked by the caller-selected trusted verifier.
type VerifiedDevice struct {
	id              UUID
	subject         string
	recipient       *age.X25519Recipient
	signingKey      ed25519.PublicKey
	assertion       []byte
	assertionDigest digest.Digest
}

func VerifyEnrollment(ctx context.Context, verifier EnrollmentVerifier, assertion []byte) (VerifiedDevice, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedDevice{}, err
	}
	if verifier == nil {
		return VerifiedDevice{}, fmt.Errorf("%w: nil verifier", ErrInvalidEnrollment)
	}
	if len(assertion) == 0 || len(assertion) > MaxEnrollmentAssertionBytes {
		return VerifiedDevice{}, fmt.Errorf("%w: assertion size", ErrInvalidEnrollment)
	}
	assertionSnapshot := append([]byte(nil), assertion...)
	claims, err := verifier.VerifyEnrollment(ctx, append([]byte(nil), assertionSnapshot...))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifiedDevice{}, ctxErr
		}
		return VerifiedDevice{}, fmt.Errorf("%w: verification failed", ErrInvalidEnrollment)
	}
	if err := claims.DeviceID.Validate(); err != nil {
		return VerifiedDevice{}, fmt.Errorf("%w: device ID: %v", ErrInvalidEnrollment, err)
	}
	if err := validatePrincipal(claims.Subject); err != nil {
		return VerifiedDevice{}, fmt.Errorf("%w: subject: %v", ErrInvalidEnrollment, err)
	}
	recipient, err := age.ParseX25519Recipient(claims.X25519Recipient)
	if err != nil || recipient.String() != claims.X25519Recipient {
		return VerifiedDevice{}, fmt.Errorf("%w: non-canonical X25519 recipient", ErrInvalidEnrollment)
	}
	if len(claims.Ed25519PublicKey) != ed25519.PublicKeySize {
		return VerifiedDevice{}, fmt.Errorf("%w: invalid Ed25519 public key", ErrInvalidEnrollment)
	}
	return VerifiedDevice{
		id:              claims.DeviceID,
		subject:         claims.Subject,
		recipient:       recipient,
		signingKey:      append(ed25519.PublicKey(nil), claims.Ed25519PublicKey...),
		assertion:       assertionSnapshot,
		assertionDigest: digest.FromBytes(assertionSnapshot),
	}, nil
}

func (d VerifiedDevice) DeviceID() UUID  { return d.id }
func (d VerifiedDevice) Subject() string { return d.subject }
func (d VerifiedDevice) RecipientString() string {
	if d.recipient == nil {
		return ""
	}
	return d.recipient.String()
}
func (d VerifiedDevice) SigningPublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), d.signingKey...)
}
func (d VerifiedDevice) AssertionDigest() digest.Digest { return d.assertionDigest }

func (d VerifiedDevice) validate() error {
	if err := d.id.Validate(); err != nil {
		return fmt.Errorf("%w: device ID: %v", ErrInvalidEnrollment, err)
	}
	if err := validatePrincipal(d.subject); err != nil {
		return fmt.Errorf("%w: subject: %v", ErrInvalidEnrollment, err)
	}
	if d.recipient == nil || len(d.signingKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: missing device keys", ErrInvalidEnrollment)
	}
	if len(d.assertion) == 0 || len(d.assertion) > MaxEnrollmentAssertionBytes {
		return fmt.Errorf("%w: assertion size", ErrInvalidEnrollment)
	}
	if digest.FromBytes(d.assertion) != d.assertionDigest {
		return fmt.Errorf("%w: assertion digest mismatch", ErrInvalidEnrollment)
	}
	return nil
}

func validatePrincipal(value string) error {
	if value == "" || len(value) > 253 || !utf8.ValidString(value) || !norm.NFC.IsNormalString(value) {
		return errors.New("must be non-empty NFC UTF-8 text of at most 253 bytes")
	}
	if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("must not contain control characters")
	}
	return nil
}

type CredentialProtection string

const CredentialProtectionOS CredentialProtection = "os-protected"

// CredentialStore is implemented by PR6 native keychain backends. The legacy
// plaintext backend does not implement this interface.
type CredentialStore interface {
	Protection() CredentialProtection
	Store(context.Context, string, []byte) error
	Load(context.Context, string) ([]byte, error)
	Delete(context.Context, string) error
}

type deviceCredential struct {
	APIVersion  string `cbor:"apiVersion"`
	Kind        string `cbor:"kind"`
	DeviceID    UUID   `cbor:"deviceID"`
	AgeIdentity string `cbor:"ageIdentity"`
	SigningSeed []byte `cbor:"signingSeed"`
}

func SaveDeviceIdentity(ctx context.Context, store CredentialStore, identity *DeviceIdentity) error {
	if err := requireProtectedStore(store); err != nil {
		return err
	}
	if err := identity.validate(); err != nil {
		return err
	}
	credential := deviceCredential{
		APIVersion:  deviceCredentialAPIVersion,
		Kind:        deviceCredentialKind,
		DeviceID:    identity.id,
		AgeIdentity: identity.recipient.String(),
		SigningSeed: append([]byte(nil), identity.signingKey.Seed()...),
	}
	data, err := MarshalCanonical(credential)
	clearBytes(credential.SigningSeed)
	if err != nil {
		return fmt.Errorf("encode device credential: %w", err)
	}
	defer clearBytes(data)
	if len(data) > MaxDeviceCredentialBytes {
		return fmt.Errorf("%w: encoded credential exceeds limit", ErrInvalidDeviceCredential)
	}
	if err := store.Store(ctx, deviceCredentialName, data); err != nil {
		return fmt.Errorf("store device credential: %w", err)
	}
	return nil
}

func LoadDeviceIdentity(ctx context.Context, store CredentialStore) (*DeviceIdentity, error) {
	if err := requireProtectedStore(store); err != nil {
		return nil, err
	}
	data, err := store.Load(ctx, deviceCredentialName)
	if err != nil {
		return nil, fmt.Errorf("load device credential: %w", err)
	}
	defer clearBytes(data)
	if len(data) == 0 || len(data) > MaxDeviceCredentialBytes {
		return nil, fmt.Errorf("%w: encoded credential size", ErrInvalidDeviceCredential)
	}
	var credential deviceCredential
	if err := UnmarshalStrict(data, &credential); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDeviceCredential, err)
	}
	defer clearBytes(credential.SigningSeed)
	canonical, err := MarshalCanonical(credential)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDeviceCredential, err)
	}
	defer clearBytes(canonical)
	if !bytes.Equal(data, canonical) {
		return nil, fmt.Errorf("%w: non-canonical encoding", ErrInvalidDeviceCredential)
	}
	if credential.APIVersion != deviceCredentialAPIVersion || credential.Kind != deviceCredentialKind {
		return nil, fmt.Errorf("%w: unsupported credential type", ErrInvalidDeviceCredential)
	}
	if err := credential.DeviceID.Validate(); err != nil {
		return nil, fmt.Errorf("%w: device ID: %v", ErrInvalidDeviceCredential, err)
	}
	recipient, err := age.ParseX25519Identity(credential.AgeIdentity)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid X25519 identity", ErrInvalidDeviceCredential)
	}
	if len(credential.SigningSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: invalid signing seed", ErrInvalidDeviceCredential)
	}
	signingKey := ed25519.NewKeyFromSeed(credential.SigningSeed)
	identity := &DeviceIdentity{id: credential.DeviceID, recipient: recipient, signingKey: signingKey}
	if err := identity.validate(); err != nil {
		return nil, err
	}
	return identity, nil
}

func DeleteDeviceIdentity(ctx context.Context, store CredentialStore) error {
	if err := requireProtectedStore(store); err != nil {
		return err
	}
	if err := store.Delete(ctx, deviceCredentialName); err != nil {
		return fmt.Errorf("delete device credential: %w", err)
	}
	return nil
}

func requireProtectedStore(store CredentialStore) error {
	if store == nil || store.Protection() != CredentialProtectionOS {
		return ErrInsecureCredentialStore
	}
	return nil
}

func clearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

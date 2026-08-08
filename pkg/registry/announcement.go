package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/opencontainers/go-digest"
)

const (
	AnnouncementAPIVersion  = "artifacts.enbu.net/v1alpha1"
	AnnouncementKind        = "CommitAnnouncement"
	MaxAnnouncementBytes    = 64 * 1024
	MaxEncryptedCommitBytes = commitmodel.MaxCommitBytes + 64*1024

	announcementSignatureDomain = "enbu.net/commit-announcement/v1\x00"
	announcementTagPrefix       = "commit-"
)

// CommitAnnouncement is public registry metadata. Actor, Device ID, signing
// keys, operation, timestamp, parents, and graph content remain inside its
// encrypted Grant and signed Commit.
type CommitAnnouncement struct {
	APIVersion      string              `cbor:"apiVersion" json:"apiVersion"`
	Kind            string              `cbor:"kind" json:"kind"`
	WorkspaceID     artifact.UUID       `cbor:"workspaceID" json:"workspaceID"`
	CommitID        digest.Digest       `cbor:"commitID" json:"commitID"`
	EncryptedCommit artifact.Descriptor `cbor:"encryptedCommit" json:"encryptedCommit"`
	Grant           artifact.Descriptor `cbor:"grant" json:"grant"`
	Signature       []byte              `cbor:"signature" json:"signature"`
}

type announcementBody struct {
	APIVersion      string              `cbor:"apiVersion"`
	Kind            string              `cbor:"kind"`
	WorkspaceID     artifact.UUID       `cbor:"workspaceID"`
	CommitID        digest.Digest       `cbor:"commitID"`
	EncryptedCommit artifact.Descriptor `cbor:"encryptedCommit"`
	Grant           artifact.Descriptor `cbor:"grant"`
}

func NewCommitAnnouncement(
	workspaceID artifact.UUID,
	commitID digest.Digest,
	encryptedCommit artifact.Descriptor,
	grant artifact.Descriptor,
	publisher *artifact.DeviceIdentity,
	publisherEnrollment artifact.VerifiedDevice,
) (CommitAnnouncement, error) {
	if publisher == nil || publisher.DeviceID() != publisherEnrollment.DeviceID() ||
		publisher.RecipientString() != publisherEnrollment.RecipientString() ||
		!bytes.Equal(publisher.SigningPublicKey(), publisherEnrollment.SigningPublicKey()) {
		return CommitAnnouncement{}, fmt.Errorf("%w: publisher enrollment mismatch", ErrInvalidAnnouncement)
	}
	announcement := CommitAnnouncement{
		APIVersion:      AnnouncementAPIVersion,
		Kind:            AnnouncementKind,
		WorkspaceID:     workspaceID,
		CommitID:        commitID,
		EncryptedCommit: encryptedCommit,
		Grant:           grant,
	}
	unsigned, err := encodeAnnouncementBody(announcement.body())
	if err != nil {
		return CommitAnnouncement{}, err
	}
	announcement.Signature, err = publisher.Sign(announcementSigningMessage(unsigned))
	if err != nil {
		return CommitAnnouncement{}, err
	}
	if err := announcement.Validate(); err != nil {
		return CommitAnnouncement{}, err
	}
	return announcement, nil
}

func (a CommitAnnouncement) Validate() error {
	if a.APIVersion != AnnouncementAPIVersion || a.Kind != AnnouncementKind {
		return fmt.Errorf("%w: unsupported envelope type", ErrInvalidAnnouncement)
	}
	if err := a.WorkspaceID.Validate(); err != nil {
		return fmt.Errorf("%w: workspace ID: %v", ErrInvalidAnnouncement, err)
	}
	if err := validateDigest(a.CommitID); err != nil {
		return fmt.Errorf("%w: commit ID: %v", ErrInvalidAnnouncement, err)
	}
	if err := validateDescriptor(a.EncryptedCommit, artifact.MediaTypeEncryptedCommit); err != nil {
		return fmt.Errorf("%w: encrypted Commit: %v", ErrInvalidAnnouncement, err)
	}
	if a.EncryptedCommit.Size > MaxEncryptedCommitBytes {
		return fmt.Errorf("%w: encrypted Commit exceeds size limit", ErrInvalidAnnouncement)
	}
	if err := validateDescriptor(a.Grant, artifact.MediaTypeAccessGrant); err != nil {
		return fmt.Errorf("%w: Grant: %v", ErrInvalidAnnouncement, err)
	}
	if a.Grant.Size > artifact.MaxGrantBytes {
		return fmt.Errorf("%w: Grant exceeds size limit", ErrInvalidAnnouncement)
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature size", ErrInvalidAnnouncement)
	}
	return nil
}

func EncodeCommitAnnouncement(announcement CommitAnnouncement) ([]byte, error) {
	if err := announcement.Validate(); err != nil {
		return nil, err
	}
	encoded, err := artifact.MarshalCanonical(announcement)
	if err != nil {
		return nil, fmt.Errorf("encode commit announcement: %w", err)
	}
	if len(encoded) > MaxAnnouncementBytes {
		return nil, fmt.Errorf("%w: encoded announcement exceeds limit", ErrInvalidAnnouncement)
	}
	return encoded, nil
}

func DecodeCommitAnnouncement(data []byte) (CommitAnnouncement, error) {
	if len(data) == 0 || len(data) > MaxAnnouncementBytes {
		return CommitAnnouncement{}, fmt.Errorf("%w: encoded size", ErrInvalidAnnouncement)
	}
	var announcement CommitAnnouncement
	if err := artifact.UnmarshalStrict(data, &announcement); err != nil {
		return CommitAnnouncement{}, fmt.Errorf("%w: %v", ErrInvalidAnnouncement, err)
	}
	canonical, err := EncodeCommitAnnouncement(announcement)
	if err != nil {
		return CommitAnnouncement{}, err
	}
	if !bytes.Equal(data, canonical) {
		return CommitAnnouncement{}, fmt.Errorf("%w: non-canonical encoding", ErrInvalidAnnouncement)
	}
	return announcement, nil
}

func VerifyCommitAnnouncement(ctx context.Context, announcement CommitAnnouncement, publicKey ed25519.PublicKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := announcement.Validate(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: publisher key binding", ErrInvalidAnnouncementSignature)
	}
	unsigned, err := encodeAnnouncementBody(announcement.body())
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, announcementSigningMessage(unsigned), announcement.Signature) {
		return ErrInvalidAnnouncementSignature
	}
	return nil
}

func AnnouncementTag(announcementDigest digest.Digest) (string, error) {
	if err := validateDigest(announcementDigest); err != nil {
		return "", err
	}
	return announcementTagPrefix + announcementDigest.Encoded(), nil
}

func ParseAnnouncementTag(tag string) (digest.Digest, error) {
	if !strings.HasPrefix(tag, announcementTagPrefix) {
		return "", fmt.Errorf("%w: missing prefix", ErrInvalidAnnouncement)
	}
	hex := strings.TrimPrefix(tag, announcementTagPrefix)
	if len(hex) != 64 || strings.ToLower(hex) != hex {
		return "", fmt.Errorf("%w: malformed tag digest", ErrInvalidAnnouncement)
	}
	parsed := digest.NewDigestFromEncoded(digest.SHA256, hex)
	if err := validateDigest(parsed); err != nil {
		return "", fmt.Errorf("%w: malformed tag digest", ErrInvalidAnnouncement)
	}
	return parsed, nil
}

func (a CommitAnnouncement) body() announcementBody {
	return announcementBody{
		APIVersion:      a.APIVersion,
		Kind:            a.Kind,
		WorkspaceID:     a.WorkspaceID,
		CommitID:        a.CommitID,
		EncryptedCommit: a.EncryptedCommit,
		Grant:           a.Grant,
	}
}

func encodeAnnouncementBody(body announcementBody) ([]byte, error) {
	encoded, err := artifact.MarshalCanonical(body)
	if err != nil {
		return nil, fmt.Errorf("encode announcement signature body: %w", err)
	}
	return encoded, nil
}

func announcementSigningMessage(unsigned []byte) []byte {
	message := make([]byte, 0, len(announcementSignatureDomain)+len(unsigned))
	message = append(message, announcementSignatureDomain...)
	return append(message, unsigned...)
}

func validateDescriptor(descriptor artifact.Descriptor, mediaType string) error {
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if descriptor.MediaType != mediaType || descriptor.Size <= 0 {
		return errors.New("unexpected descriptor media type or size")
	}
	return nil
}

func validateDigest(value digest.Digest) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.Algorithm() != digest.SHA256 || value.String() != "sha256:"+value.Encoded() {
		return errors.New("digest must be canonical sha256")
	}
	return nil
}

package commit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

func TestSealOpenCommitSeparatesLogicalAndCiphertextIdentity(t *testing.T) {
	t.Parallel()

	signer, author, enrollments := newSealedTestDevice(t)
	value := baseCommit(1, nil)
	value.DeviceID = signer.DeviceID()
	objects := newSealedTestObjects()

	first, err := SealCommit(context.Background(), objects, value, signer, author)
	if err != nil {
		t.Fatalf("SealCommit first: %v", err)
	}
	second, err := SealCommit(context.Background(), objects, value, signer, author)
	if err != nil {
		t.Fatalf("SealCommit second: %v", err)
	}
	if first.CommitID() != second.CommitID() {
		t.Fatalf("logical IDs differ: %s vs %s", first.CommitID(), second.CommitID())
	}
	if first.Descriptor() == second.Descriptor() || first.MaterialRecipient() == second.MaterialRecipient() {
		t.Fatal("randomized ciphertext descriptors unexpectedly match")
	}

	grant, err := first.CreateAccessGrant(context.Background(), value.Policy.Revision, signer, []artifact.VerifiedDevice{author})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}
	opened := openSealedTestGrant(t, grant, signer, enrollments)
	verified, err := OpenCommit(context.Background(), objects, opened, first.Descriptor(), first.CommitID(), enrollments)
	if err != nil {
		t.Fatalf("OpenCommit: %v", err)
	}
	if verified.Digest() != first.CommitID() || verified.Commit().WorkspaceID != value.WorkspaceID {
		t.Fatalf("opened Commit = %#v", verified.Commit())
	}
	if verified.SignerKeyID() != digest.FromBytes(signer.SigningPublicKey()) {
		t.Fatalf("SignerKeyID = %s", verified.SignerKeyID())
	}
}

func TestOpenCommitRejectsIdentityDescriptorAndLogicalIDSubstitution(t *testing.T) {
	t.Parallel()

	signer, author, enrollments := newSealedTestDevice(t)
	value := baseCommit(1, nil)
	value.DeviceID = signer.DeviceID()
	objects := newSealedTestObjects()
	sealed, err := SealCommit(context.Background(), objects, value, signer, author)
	if err != nil {
		t.Fatalf("SealCommit: %v", err)
	}
	grant, err := sealed.CreateAccessGrant(context.Background(), value.Policy.Revision, signer, []artifact.VerifiedDevice{author})
	if err != nil {
		t.Fatalf("CreateAccessGrant: %v", err)
	}
	opened := openSealedTestGrant(t, grant, signer, enrollments)

	other, err := SealCommit(context.Background(), objects, value, signer, author)
	if err != nil {
		t.Fatalf("SealCommit other: %v", err)
	}
	otherGrant, err := other.CreateAccessGrant(context.Background(), value.Policy.Revision, signer, []artifact.VerifiedDevice{author})
	if err != nil {
		t.Fatalf("CreateAccessGrant other: %v", err)
	}
	wrongGrant := openSealedTestGrant(t, otherGrant, signer, enrollments)
	if _, err := OpenCommit(context.Background(), objects, wrongGrant, sealed.Descriptor(), sealed.CommitID(), enrollments); err == nil {
		t.Fatal("OpenCommit accepted a Grant for a different encrypted Commit")
	}

	mutated := sealed.Descriptor()
	mutated.Size++
	if _, err := OpenCommit(context.Background(), objects, opened, mutated, sealed.CommitID(), enrollments); err == nil {
		t.Fatal("OpenCommit accepted a substituted descriptor")
	}

	if _, err := OpenCommit(
		context.Background(), objects, opened, sealed.Descriptor(), digest.FromString("different Commit"), enrollments,
	); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("logical ID substitution error = %v, want ErrInvalidCommit", err)
	}
}

func TestOpenCommitPreservesCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := OpenCommit(
		ctx,
		newSealedTestObjects(),
		artifact.OpenedGrant{},
		artifact.Descriptor{MediaType: artifact.MediaTypeEncryptedCommit, Digest: digest.FromString("ciphertext"), Size: 1},
		digest.FromString("commit"),
		nil,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenCommit error = %v, want context.Canceled", err)
	}
}

type sealedEnrollmentVerifier struct {
	assertion []byte
	claims    artifact.EnrollmentClaims
}

func (v sealedEnrollmentVerifier) VerifyEnrollment(_ context.Context, assertion []byte) (artifact.EnrollmentClaims, error) {
	if !bytes.Equal(assertion, v.assertion) {
		return artifact.EnrollmentClaims{}, errors.New("unknown enrollment")
	}
	claims := v.claims
	claims.Ed25519PublicKey = append(ed25519.PublicKey(nil), claims.Ed25519PublicKey...)
	return claims, nil
}

func newSealedTestDevice(t *testing.T) (*artifact.DeviceIdentity, artifact.VerifiedDevice, sealedEnrollmentVerifier) {
	t.Helper()
	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	assertion := []byte("sealed-test:" + string(device.DeviceID()))
	verifier := sealedEnrollmentVerifier{
		assertion: assertion,
		claims: artifact.EnrollmentClaims{
			DeviceID:         device.DeviceID(),
			Subject:          testActor,
			X25519Recipient:  device.RecipientString(),
			Ed25519PublicKey: device.SigningPublicKey(),
		},
	}
	author, err := artifact.VerifyEnrollment(context.Background(), verifier, assertion)
	if err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}
	return device, author, verifier
}

func openSealedTestGrant(
	t *testing.T,
	grant artifact.AccessGrant,
	device *artifact.DeviceIdentity,
	verifier artifact.EnrollmentVerifier,
) artifact.OpenedGrant {
	t.Helper()
	encoded, err := artifact.EncodeAccessGrant(grant)
	if err != nil {
		t.Fatalf("EncodeAccessGrant: %v", err)
	}
	opened, err := artifact.OpenAccessGrant(context.Background(), encoded, device, verifier)
	if err != nil {
		t.Fatalf("OpenAccessGrant: %v", err)
	}
	return opened
}

type sealedTestObject struct {
	descriptor artifact.Descriptor
	data       []byte
}

type sealedTestObjects struct {
	objects map[digest.Digest]sealedTestObject
}

func newSealedTestObjects() *sealedTestObjects {
	return &sealedTestObjects{objects: make(map[digest.Digest]sealedTestObject)}
}

func (s *sealedTestObjects) Ingest(ctx context.Context, mediaType string, source io.Reader) (artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	data, err := io.ReadAll(source)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	descriptor := artifact.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	s.objects[descriptor.Digest] = sealedTestObject{descriptor: descriptor, data: append([]byte(nil), data...)}
	return descriptor, nil
}

func (s *sealedTestObjects) Open(ctx context.Context, objectDigest digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	object, ok := s.objects[objectDigest]
	if !ok {
		return nil, artifact.Descriptor{}, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(object.data)), object.descriptor, nil
}

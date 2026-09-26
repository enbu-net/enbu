package artifact

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestMaterialIdentityIsCanonicalAndZeroSafe(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	if !strings.HasPrefix(identity.RecipientString(), "age1") {
		t.Fatalf("RecipientString() = %q", identity.RecipientString())
	}
	secret, err := identity.marshalSecret()
	if err != nil {
		t.Fatalf("marshalSecret: %v", err)
	}
	parsed, err := parseMaterialIdentity(secret)
	if err != nil {
		t.Fatalf("parseMaterialIdentity: %v", err)
	}
	if parsed.RecipientString() != identity.RecipientString() {
		t.Fatal("parsed identity has a different recipient")
	}

	var zero MaterialIdentity
	if zero.RecipientString() != "" {
		t.Fatalf("zero RecipientString() = %q", zero.RecipientString())
	}
	if _, err := zero.marshalSecret(); !errors.Is(err, ErrMaterialIdentity) {
		t.Fatalf("zero marshalSecret = %v, want ErrMaterialIdentity", err)
	}
	if _, err := parseMaterialIdentity("not-an-age-identity"); !errors.Is(err, ErrMaterialIdentity) {
		t.Fatalf("invalid parse = %v, want ErrMaterialIdentity", err)
	}
}

func TestMaterialManifestSealOpenAndRevisionBinding(t *testing.T) {
	t.Parallel()

	fixture := newMaterialFixture(t)
	if err := fixture.manifest.ValidateForRevision(fixture.revision); err != nil {
		t.Fatalf("ValidateForRevision: %v", err)
	}

	descriptor, err := SealMaterialManifest(context.Background(), fixture.objects, fixture.identity, fixture.revision, fixture.manifest)
	if err != nil {
		t.Fatalf("SealMaterialManifest: %v", err)
	}
	if descriptor.MediaType != MediaTypeEncryptedMaterial {
		t.Fatalf("media type = %q", descriptor.MediaType)
	}
	sealed := fixture.objects.objects[descriptor.Digest].data
	for _, plaintextMetadata := range []string{fixture.revision.Metadata.Name, fixture.revision.Payloads[0].Name} {
		if bytes.Contains(sealed, []byte(plaintextMetadata)) {
			t.Fatalf("sealed material exposes plaintext metadata %q", plaintextMetadata)
		}
	}

	opened, err := OpenMaterialManifest(context.Background(), fixture.objects, fixture.identity, descriptor.Digest, fixture.manifest.Revision.Digest)
	if err != nil {
		t.Fatalf("OpenMaterialManifest: %v", err)
	}
	if !reflect.DeepEqual(opened, canonicalMaterialManifest(fixture.manifest)) {
		t.Fatalf("opened manifest differs:\n got: %#v\nwant: %#v", opened, canonicalMaterialManifest(fixture.manifest))
	}
	if err := opened.ValidateForRevision(fixture.revision); err != nil {
		t.Fatalf("opened ValidateForRevision: %v", err)
	}

	var revisionBytes bytes.Buffer
	if err := DecryptStream(context.Background(), fixture.objects, fixture.identity, opened.Revision, &revisionBytes); err != nil {
		t.Fatalf("decrypt revision: %v", err)
	}
	decoded, err := DecodeRevision(revisionBytes.Bytes())
	if err != nil {
		t.Fatalf("DecodeRevision: %v", err)
	}
	if decoded.UID != fixture.revision.UID {
		t.Fatalf("decoded revision UID = %s", decoded.UID)
	}

	var payload bytes.Buffer
	if err := DecryptStream(context.Background(), fixture.objects, fixture.identity, opened.Payloads[0].Stream, &payload); err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	if payload.String() != fixture.payload {
		t.Fatalf("payload = %q, want %q", payload.String(), fixture.payload)
	}
}

func TestMaterialManifestRejectsWrongIdentityAndRevision(t *testing.T) {
	t.Parallel()

	fixture := newMaterialFixture(t)
	descriptor, err := SealMaterialManifest(context.Background(), fixture.objects, fixture.identity, fixture.revision, fixture.manifest)
	if err != nil {
		t.Fatalf("SealMaterialManifest: %v", err)
	}
	wrongIdentity := mustMaterialIdentity(t)
	if _, err := OpenMaterialManifest(context.Background(), fixture.objects, wrongIdentity, descriptor.Digest, fixture.manifest.Revision.Digest); err == nil {
		t.Fatal("OpenMaterialManifest accepted a wrong identity")
	}
	if _, err := OpenMaterialManifest(context.Background(), fixture.objects, fixture.identity, descriptor.Digest, digest.FromString("different-revision")); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("OpenMaterialManifest(revision substitution) = %v, want ErrMaterialMismatch", err)
	}

	wrongRecipient := fixture.manifest
	wrongRecipient.Recipient = wrongIdentity.RecipientString()
	if _, err := SealMaterialManifest(context.Background(), fixture.objects, fixture.identity, fixture.revision, wrongRecipient); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("SealMaterialManifest recipient mismatch = %v, want ErrMaterialMismatch", err)
	}

	changedRevision := fixture.revision
	changedRevision.Metadata.Name = "renamed"
	if err := fixture.manifest.ValidateForRevision(changedRevision); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("changed revision = %v, want ErrMaterialMismatch", err)
	}
	if _, err := SealMaterialManifest(context.Background(), fixture.objects, fixture.identity, changedRevision, fixture.manifest); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("SealMaterialManifest(changed revision) = %v, want ErrMaterialMismatch", err)
	}

	changedPayload := fixture.manifest
	changedPayload.Payloads[0].Stream.Digest = digest.FromString("different payload")
	if err := changedPayload.ValidateForRevision(fixture.revision); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("changed payload = %v, want ErrMaterialMismatch", err)
	}
}

func TestMaterialManifestCanonicalPayloadOrderAndStrictDecode(t *testing.T) {
	t.Parallel()

	fixture := newMaterialFixture(t)
	second := fixture.manifest.Payloads[0]
	second.Name = "z-last"
	manifest := fixture.manifest
	manifest.Payloads = []MaterialPayload{second, fixture.manifest.Payloads[0]}

	encoded, err := EncodeMaterialManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeMaterialManifest: %v", err)
	}
	if manifest.Payloads[0].Name != "z-last" {
		t.Fatal("EncodeMaterialManifest mutated caller payload order")
	}
	manifest.Payloads[0], manifest.Payloads[1] = manifest.Payloads[1], manifest.Payloads[0]
	encodedSorted, err := EncodeMaterialManifest(manifest)
	if err != nil {
		t.Fatalf("EncodeMaterialManifest(sorted): %v", err)
	}
	if !bytes.Equal(encoded, encodedSorted) {
		t.Fatal("canonical encoding depends on payload order")
	}
	chunkReordered := manifest
	chunkReordered.Revision.Chunks = append([]ChunkRef(nil), manifest.Revision.Chunks...)
	for left, right := 0, len(chunkReordered.Revision.Chunks)-1; left < right; left, right = left+1, right-1 {
		chunkReordered.Revision.Chunks[left], chunkReordered.Revision.Chunks[right] = chunkReordered.Revision.Chunks[right], chunkReordered.Revision.Chunks[left]
	}
	encodedChunkReordered, err := EncodeMaterialManifest(chunkReordered)
	if err != nil {
		t.Fatalf("EncodeMaterialManifest(chunk reordered): %v", err)
	}
	if !bytes.Equal(encoded, encodedChunkReordered) {
		t.Fatal("canonical encoding depends on chunk order")
	}

	unsorted := canonicalMaterialManifest(manifest)
	unsorted.Payloads[0], unsorted.Payloads[1] = unsorted.Payloads[1], unsorted.Payloads[0]
	unsortedBytes, err := MarshalCanonical(unsorted)
	if err != nil {
		t.Fatalf("MarshalCanonical(unsorted): %v", err)
	}
	if _, err := DecodeMaterialManifest(unsortedBytes); !errors.Is(err, ErrNonCanonicalEncoding) {
		t.Fatalf("DecodeMaterialManifest(unsorted) = %v, want ErrNonCanonicalEncoding", err)
	}

	type materialWithUnknownField struct {
		APIVersion string            `cbor:"apiVersion"`
		Recipient  string            `cbor:"recipient"`
		Revision   EncryptedStream   `cbor:"revision"`
		Payloads   []MaterialPayload `cbor:"payloads,omitempty"`
		Unknown    string            `cbor:"unknown"`
	}
	unknownBytes, err := MarshalCanonical(materialWithUnknownField{
		APIVersion: manifest.APIVersion,
		Recipient:  manifest.Recipient,
		Revision:   manifest.Revision,
		Payloads:   manifest.Payloads,
		Unknown:    "rejected",
	})
	if err != nil {
		t.Fatalf("MarshalCanonical(unknown): %v", err)
	}
	if _, err := DecodeMaterialManifest(unknownBytes); err == nil {
		t.Fatal("DecodeMaterialManifest accepted an unknown field")
	}
}

func TestMaterialManifestPropagatesObjectFailures(t *testing.T) {
	t.Parallel()

	fixture := newMaterialFixture(t)
	sentinel := errors.New("object storage failed")
	if _, err := SealMaterialManifest(context.Background(), errorSink{err: sentinel}, fixture.identity, fixture.revision, fixture.manifest); !errors.Is(err, sentinel) {
		t.Fatalf("SealMaterialManifest error = %v, want sentinel", err)
	}
	if _, err := OpenMaterialManifest(context.Background(), errorSource{err: sentinel}, fixture.identity, digest.FromString("material"), fixture.manifest.Revision.Digest); !errors.Is(err, sentinel) {
		t.Fatalf("OpenMaterialManifest error = %v, want sentinel", err)
	}
}

func TestEncryptedStreamValidatesContiguousBoundaries(t *testing.T) {
	t.Parallel()

	fixture := newMaterialFixture(t)
	stream := fixture.manifest.Revision
	stream.Chunks[0].Offset = 1
	if err := stream.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("non-contiguous stream = %v, want ErrInvalidArtifact", err)
	}
	stream = fixture.manifest.Revision
	stream.Chunks[0].Ciphertext.MediaType = "application/octet-stream"
	if err := stream.Validate(); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("wrong chunk media type = %v, want ErrInvalidArtifact", err)
	}
}

type materialFixture struct {
	identity MaterialIdentity
	objects  *memoryObjects
	revision Revision
	payload  string
	manifest MaterialManifest
}

func newMaterialFixture(t *testing.T) materialFixture {
	t.Helper()
	identity := mustMaterialIdentity(t)
	objects := newMemoryObjects()
	revision := validResource()
	payload := "plaintext"
	revisionBytes, err := EncodeRevision(revision)
	if err != nil {
		t.Fatalf("EncodeRevision: %v", err)
	}
	revisionStream, err := encryptStream(context.Background(), objects, identity, bytes.NewReader(revisionBytes), 128)
	if err != nil {
		t.Fatalf("encrypt revision: %v", err)
	}
	payloadStream, err := encryptStream(context.Background(), objects, identity, strings.NewReader(payload), 4)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	manifest := MaterialManifest{
		APIVersion: APIVersion,
		Recipient:  identity.RecipientString(),
		Revision:   revisionStream,
		Payloads: []MaterialPayload{{
			Name:   revision.Payloads[0].Name,
			Stream: payloadStream,
		}},
	}
	return materialFixture{
		identity: identity,
		objects:  objects,
		revision: revision,
		payload:  payload,
		manifest: manifest,
	}
}

var _ io.Writer = (*bytes.Buffer)(nil)

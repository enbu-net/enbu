package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/enrollment"
	"github.com/opencontainers/go-digest"
)

func TestSealOpenRevisionSupportsOpaqueBinaryWithoutFormatBranching(t *testing.T) {
	t.Parallel()

	objects := newMemoryObjects()
	device, verified, verifier := testDevice(t)
	schema, err := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x00, 0xff, 0x10, 'S', 'S', 'I', 'D', '=', 'x'}
	draft := Draft{
		Kind:     artifact.KindResource,
		UID:      testUUID(t, "11111111-1111-4111-8111-111111111111"),
		Schema:   schema,
		Metadata: artifact.Metadata{Name: "firmware-image", Labels: map[string]string{"format": "vendor-x"}},
		Payloads: []PayloadSource{{Name: "data", MediaType: "application/octet-stream", Reader: bytes.NewReader(payload)}},
	}
	sealed, err := (Sealer{Sink: objects, Issuer: device, Recipients: []artifact.VerifiedDevice{verified}}).
		SealDraft(context.Background(), draft, digest.FromString("owner policy"))
	if err != nil {
		t.Fatalf("SealDraft: %v", err)
	}
	if sealed.Revision.Payloads[0].Digest != digest.FromBytes(payload) {
		t.Fatal("payload digest was not derived from plaintext")
	}
	revisionBytes, err := artifact.EncodeRevision(sealed.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Ref.Revision != digest.FromBytes(revisionBytes) {
		t.Fatal("sealed reference does not bind the canonical revision")
	}
	for _, object := range objects.values {
		if bytes.Contains(object.data, payload) || bytes.Contains(object.data, []byte("firmware-image")) {
			t.Fatal("stored object contains plaintext payload or metadata")
		}
	}

	opened, err := OpenRevision(context.Background(), objects, device, verifier, sealed.Ref)
	if err != nil {
		t.Fatalf("OpenRevision: %v", err)
	}
	if opened.Revision.UID != draft.UID || opened.Revision.Schema != schema {
		t.Fatalf("opened Revision = %#v", opened.Revision)
	}
	var output bytes.Buffer
	if err := opened.WritePayload(context.Background(), objects, "data", &output); err != nil {
		t.Fatalf("WritePayload: %v", err)
	}
	if !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("payload = %x, want %x", output.Bytes(), payload)
	}
}

func TestSealDraftSupportsCollectionAndRejectsReaderFailure(t *testing.T) {
	t.Parallel()

	objects := newMemoryObjects()
	device, verified, _ := testDevice(t)
	sealer := Sealer{Sink: objects, Issuer: device, Recipients: []artifact.VerifiedDevice{verified}}
	collectionSchema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/ValueTree")
	collection, err := sealer.SealDraft(context.Background(), Draft{
		Kind: artifact.KindCollection, UID: testUUID(t, "22222222-2222-4222-8222-222222222222"),
		Schema: collectionSchema, Metadata: artifact.Metadata{Name: "root"},
	}, digest.FromString("policy"))
	if err != nil {
		t.Fatalf("SealDraft(Collection): %v", err)
	}
	if len(collection.Revision.Payloads) != 0 || len(collection.Closure.Chunks) == 0 {
		t.Fatalf("collection closure = %#v", collection)
	}

	sentinel := errors.New("input failed midstream")
	_, err = sealer.SealDraft(context.Background(), Draft{
		Kind: artifact.KindResource, UID: testUUID(t, "33333333-3333-4333-8333-333333333333"),
		Schema: collectionSchema, Metadata: artifact.Metadata{Name: "broken"},
		Payloads: []PayloadSource{{Name: "data", MediaType: "application/octet-stream", Reader: io.MultiReader(strings.NewReader("prefix"), errorReader{err: sentinel})}},
	}, digest.FromString("policy"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("SealDraft reader error = %v, want sentinel", err)
	}
}

func TestOpenRevisionRejectsGrantDescriptorAndContentSubstitution(t *testing.T) {
	t.Parallel()

	objects := newMemoryObjects()
	device, verified, verifier := testDevice(t)
	schema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	sealed, err := (Sealer{Sink: objects, Issuer: device, Recipients: []artifact.VerifiedDevice{verified}}).SealDraft(
		context.Background(),
		Draft{Kind: artifact.KindResource, UID: testUUID(t, "44444444-4444-4444-8444-444444444444"), Schema: schema, Metadata: artifact.Metadata{Name: "opaque"}, Payloads: []PayloadSource{{Name: "data", MediaType: "application/octet-stream", Reader: strings.NewReader("secret")}}},
		digest.FromString("policy"),
	)
	if err != nil {
		t.Fatal(err)
	}

	object := objects.values[sealed.Ref.Grant]
	object.descriptor.Size++
	objects.values[sealed.Ref.Grant] = object
	if _, err := OpenRevision(context.Background(), objects, device, verifier, sealed.Ref); !errors.Is(err, ErrObjectMismatch) {
		t.Fatalf("OpenRevision descriptor mismatch = %v", err)
	}

	object.descriptor.Size--
	object.data[0] ^= 0xff
	objects.values[sealed.Ref.Grant] = object
	if _, err := OpenRevision(context.Background(), objects, device, verifier, sealed.Ref); !errors.Is(err, ErrObjectMismatch) {
		t.Fatalf("OpenRevision content mismatch = %v", err)
	}
}

type storedObject struct {
	descriptor artifact.Descriptor
	data       []byte
}

type memoryObjects struct {
	values map[digest.Digest]storedObject
}

func newMemoryObjects() *memoryObjects {
	return &memoryObjects{values: map[digest.Digest]storedObject{}}
}

func (objects *memoryObjects) Ingest(ctx context.Context, mediaType string, reader io.Reader) (artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	descriptor := artifact.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	objects.values[descriptor.Digest] = storedObject{descriptor: descriptor, data: append([]byte(nil), data...)}
	return descriptor, nil
}

func (objects *memoryObjects) Open(ctx context.Context, value digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	object, ok := objects.values[value]
	if !ok {
		return nil, artifact.Descriptor{}, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(object.data)), object.descriptor, nil
}

func testDevice(t *testing.T) (*artifact.DeviceIdentity, artifact.VerifiedDevice, *enrollment.Verifier) {
	t.Helper()
	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := enrollment.NewAuthority("identity.enbu.test", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := enrollment.NewVerifier([]enrollment.Authority{authority})
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := enrollment.Sign(enrollment.Claims{
		Issuer: "identity.enbu.test", DeviceID: device.DeviceID(), Subject: "github:12345",
		X25519Recipient: device.RecipientString(), Ed25519PublicKey: device.SigningPublicKey(),
	}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifact.VerifyEnrollment(context.Background(), verifier, assertion)
	if err != nil {
		t.Fatal(err)
	}
	return device, verified, verifier
}

func testUUID(t *testing.T, value string) artifact.UUID {
	t.Helper()
	parsed, err := artifact.ParseUUID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

type errorReader struct{ err error }

func (reader errorReader) Read([]byte) (int, error) { return 0, reader.err }

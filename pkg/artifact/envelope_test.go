package artifact

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestEncryptedEnvelopeRoundTripAndExactDescriptor(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	objects := newMemoryObjects()
	plaintext := []byte("signed commit bytes")
	descriptor, err := SealEncryptedEnvelope(
		context.Background(),
		objects,
		identity,
		MediaTypeEncryptedCommit,
		bytes.NewReader(plaintext),
	)
	if err != nil {
		t.Fatalf("SealEncryptedEnvelope: %v", err)
	}

	var opened bytes.Buffer
	if err := OpenEncryptedEnvelope(context.Background(), objects, identity, descriptor, &opened); err != nil {
		t.Fatalf("OpenEncryptedEnvelope: %v", err)
	}
	if !bytes.Equal(opened.Bytes(), plaintext) {
		t.Fatal("opened plaintext differs")
	}

	mutated := descriptor
	mutated.Size++
	if err := OpenEncryptedEnvelope(context.Background(), objects, identity, mutated, &bytes.Buffer{}); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("descriptor mutation error = %v, want ErrMaterialMismatch", err)
	}
}

func TestEncryptedEnvelopeRejectsWrongIdentityAndUnsupportedMedia(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	objects := newMemoryObjects()
	if _, err := SealEncryptedEnvelope(
		context.Background(), objects, identity, MediaTypeEncryptedChunk, bytes.NewReader(nil),
	); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("unsupported seal media error = %v, want ErrInvalidArtifact", err)
	}

	descriptor, err := SealEncryptedEnvelope(
		context.Background(), objects, identity, MediaTypeEncryptedAuditSegment, bytes.NewReader([]byte("audit")),
	)
	if err != nil {
		t.Fatalf("SealEncryptedEnvelope: %v", err)
	}
	if err := OpenEncryptedEnvelope(
		context.Background(), objects, mustMaterialIdentity(t), descriptor, &bytes.Buffer{},
	); err == nil {
		t.Fatal("OpenEncryptedEnvelope accepted a different identity")
	}

	mutated := descriptor
	mutated.MediaType = MediaTypeEncryptedMaterial
	if err := OpenEncryptedEnvelope(context.Background(), objects, identity, mutated, &bytes.Buffer{}); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("unsupported open media error = %v, want ErrInvalidArtifact", err)
	}
}

func TestEncryptedEnvelopeClassifiesMalformedCiphertext(t *testing.T) {
	t.Parallel()

	objects := newMemoryObjects()
	malformed := []byte("not an age envelope")
	descriptor := Descriptor{
		MediaType: MediaTypeEncryptedCommit,
		Digest:    digest.FromBytes(malformed),
		Size:      int64(len(malformed)),
	}
	objects.objects[descriptor.Digest] = storedObject{descriptor: descriptor, data: malformed}

	err := OpenEncryptedEnvelope(
		context.Background(), objects, mustMaterialIdentity(t), descriptor, &bytes.Buffer{},
	)
	if !errors.Is(err, ErrInvalidEncryptedObject) {
		t.Fatalf("OpenEncryptedEnvelope malformed ciphertext = %v, want ErrInvalidEncryptedObject", err)
	}
}

func TestEncryptedEnvelopePreservesCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	identity := mustMaterialIdentity(t)
	objects := newMemoryObjects()
	if _, err := SealEncryptedEnvelope(ctx, objects, identity, MediaTypeEncryptedCommit, bytes.NewReader(nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("SealEncryptedEnvelope error = %v, want context.Canceled", err)
	}
}

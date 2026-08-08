package artifact

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
)

func TestEncryptDecryptStreamEmptyAndMultiChunk(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	for name, plaintext := range map[string][]byte{
		"empty":       {},
		"multi-chunk": bytes.Repeat([]byte("confidential-data/"), 700),
	} {
		plaintext := plaintext
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			objects := newMemoryObjects()
			stream, err := encryptStream(context.Background(), objects, identity, bytes.NewReader(plaintext), 1024)
			if err != nil {
				t.Fatalf("encryptStream: %v", err)
			}
			if stream.Digest != digest.FromBytes(plaintext) || stream.Size != int64(len(plaintext)) {
				t.Fatalf("stream identity = %s/%d, want %s/%d", stream.Digest, stream.Size, digest.FromBytes(plaintext), len(plaintext))
			}
			if len(plaintext) == 0 && (len(stream.Chunks) != 1 || stream.Chunks[0].PlaintextSize != 0) {
				t.Fatalf("empty stream chunks = %#v, want one authenticated empty chunk", stream.Chunks)
			}
			if len(plaintext) > 1024 && len(stream.Chunks) < 2 {
				t.Fatalf("multi-chunk stream has %d chunks", len(stream.Chunks))
			}

			var decrypted bytes.Buffer
			if err := DecryptStream(context.Background(), objects, identity, stream, &decrypted); err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}
			if !bytes.Equal(decrypted.Bytes(), plaintext) {
				t.Fatal("decrypted plaintext differs")
			}
		})
	}
}

func TestStreamChunkingDoesNotChangePlaintextIdentity(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	plaintext := bytes.Repeat([]byte("chunk-boundaries-are-storage-only"), 100)
	firstStore := newMemoryObjects()
	first, err := encryptStream(context.Background(), firstStore, identity, bytes.NewReader(plaintext), 127)
	if err != nil {
		t.Fatalf("encrypt first stream: %v", err)
	}
	secondStore := newMemoryObjects()
	second, err := encryptStream(context.Background(), secondStore, identity, bytes.NewReader(plaintext), 1024)
	if err != nil {
		t.Fatalf("encrypt second stream: %v", err)
	}
	if first.Digest != second.Digest || first.Size != second.Size {
		t.Fatalf("plaintext identity depends on chunks: %#v vs %#v", first, second)
	}
	if len(first.Chunks) == len(second.Chunks) {
		t.Fatalf("test did not produce distinct chunking: %d", len(first.Chunks))
	}
}

func TestDecryptStreamUsesCanonicalOffsetOrder(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	plaintext := bytes.Repeat([]byte("ordered-by-offset"), 100)
	objects := newMemoryObjects()
	stream, err := encryptStream(context.Background(), objects, identity, bytes.NewReader(plaintext), 97)
	if err != nil {
		t.Fatalf("encryptStream: %v", err)
	}
	for left, right := 0, len(stream.Chunks)-1; left < right; left, right = left+1, right-1 {
		stream.Chunks[left], stream.Chunks[right] = stream.Chunks[right], stream.Chunks[left]
	}
	var decrypted bytes.Buffer
	if err := DecryptStream(context.Background(), objects, identity, stream, &decrypted); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatal("decrypted plaintext differs")
	}
}

func TestDecryptStreamRejectsWrongKeyTamperingAndTruncation(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	plaintext := bytes.Repeat([]byte("authenticated"), 200)
	objects := newMemoryObjects()
	stream, err := encryptStream(context.Background(), objects, identity, bytes.NewReader(plaintext), 512)
	if err != nil {
		t.Fatalf("encrypt stream: %v", err)
	}

	t.Run("wrong key", func(t *testing.T) {
		wrongIdentity := mustMaterialIdentity(t)
		if err := DecryptStream(context.Background(), objects, wrongIdentity, stream, io.Discard); err == nil {
			t.Fatal("DecryptStream accepted a wrong identity")
		}
	})

	t.Run("tampering", func(t *testing.T) {
		tampered := objects.clone()
		object := tampered.objects[stream.Chunks[0].Ciphertext.Digest]
		object.data[len(object.data)/2] ^= 0x80
		tampered.objects[stream.Chunks[0].Ciphertext.Digest] = object
		if err := DecryptStream(context.Background(), tampered, identity, stream, io.Discard); err == nil {
			t.Fatal("DecryptStream accepted tampered ciphertext")
		}
	})

	t.Run("truncation", func(t *testing.T) {
		truncated := objects.clone()
		object := truncated.objects[stream.Chunks[len(stream.Chunks)-1].Ciphertext.Digest]
		object.data = object.data[:len(object.data)-1]
		truncated.objects[object.descriptor.Digest] = object
		if err := DecryptStream(context.Background(), truncated, identity, stream, io.Discard); err == nil {
			t.Fatal("DecryptStream accepted truncated ciphertext")
		}
	})
}

func TestStreamPropagatesObjectAndPlaintextFailures(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	sentinel := errors.New("storage unavailable")

	if _, err := EncryptStream(context.Background(), errorSink{err: sentinel}, identity, strings.NewReader("secret")); !errors.Is(err, sentinel) {
		t.Fatalf("EncryptStream sink error = %v, want sentinel", err)
	}

	objects := newMemoryObjects()
	stream, err := EncryptStream(context.Background(), objects, identity, strings.NewReader("secret"))
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	if err := DecryptStream(context.Background(), errorSource{err: sentinel}, identity, stream, io.Discard); !errors.Is(err, sentinel) {
		t.Fatalf("DecryptStream source error = %v, want sentinel", err)
	}
	if err := DecryptStream(context.Background(), objects, identity, stream, errorWriter{err: sentinel}); !errors.Is(err, sentinel) {
		t.Fatalf("DecryptStream destination error = %v, want sentinel", err)
	}

	readerError := errors.New("input failed")
	if _, err := EncryptStream(context.Background(), newMemoryObjects(), identity, &errorReader{data: []byte("partial"), err: readerError}); !errors.Is(err, readerError) {
		t.Fatalf("EncryptStream reader error = %v, want sentinel", err)
	}
}

func TestStreamVerifiesObjectDescriptors(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	badSinkObjects := newMemoryObjects()
	if _, err := EncryptStream(
		context.Background(),
		mutatingDescriptorSink{sink: badSinkObjects},
		identity,
		strings.NewReader("secret"),
	); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("EncryptStream bad descriptor = %v, want ErrMaterialMismatch", err)
	}

	objects := newMemoryObjects()
	stream, err := EncryptStream(context.Background(), objects, identity, strings.NewReader("secret"))
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	if err := DecryptStream(
		context.Background(),
		mutatingDescriptorSource{source: objects},
		identity,
		stream,
		io.Discard,
	); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("DecryptStream bad descriptor = %v, want ErrMaterialMismatch", err)
	}

	manifestSizeMismatch := stream
	manifestSizeMismatch.Chunks = append([]ChunkRef(nil), stream.Chunks...)
	manifestSizeMismatch.Chunks[0].Ciphertext.Size++
	if err := DecryptStream(context.Background(), objects, identity, manifestSizeMismatch, io.Discard); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("DecryptStream manifest descriptor mismatch = %v, want ErrMaterialMismatch", err)
	}
}

func TestStreamHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := EncryptStream(ctx, newMemoryObjects(), identity, strings.NewReader("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("EncryptStream canceled = %v", err)
	}

	objects := newMemoryObjects()
	stream, err := EncryptStream(context.Background(), objects, identity, strings.NewReader("secret"))
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	if err := DecryptStream(ctx, objects, identity, stream, io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("DecryptStream canceled = %v", err)
	}
}

func TestEncryptStreamBoundsSourceReadSize(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	reader := &boundedRequestReader{
		reader: bytes.NewReader(bytes.Repeat([]byte("x"), 4097)),
		limit:  257,
	}
	stream, err := encryptStream(context.Background(), newMemoryObjects(), identity, reader, 257)
	if err != nil {
		t.Fatalf("encryptStream: %v", err)
	}
	if stream.Size != 4097 {
		t.Fatalf("size = %d, want 4097", stream.Size)
	}
	if reader.maxRequested > reader.limit {
		t.Fatalf("source read request = %d, want <= %d", reader.maxRequested, reader.limit)
	}
}

func TestDecryptStreamRejectsPlaintextBindingMismatch(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	objects := newMemoryObjects()
	stream, err := EncryptStream(context.Background(), objects, identity, strings.NewReader("secret"))
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	stream.Digest = digest.FromString("another plaintext")
	if err := DecryptStream(context.Background(), objects, identity, stream, io.Discard); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("DecryptStream mismatch = %v, want ErrMaterialMismatch", err)
	}
}

func TestDecryptStreamBoundsOutputByDeclaredChunkSize(t *testing.T) {
	t.Parallel()

	identity := mustMaterialIdentity(t)
	objects := newMemoryObjects()
	stream, err := EncryptStream(context.Background(), objects, identity, strings.NewReader("secret"))
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	stream.Chunks = append([]ChunkRef(nil), stream.Chunks...)
	stream.Chunks[0].PlaintextSize--
	stream.Size--

	var destination bytes.Buffer
	if err := DecryptStream(context.Background(), objects, identity, stream, &destination); !errors.Is(err, ErrMaterialMismatch) {
		t.Fatalf("DecryptStream oversized plaintext = %v, want ErrMaterialMismatch", err)
	}
	if int64(destination.Len()) > stream.Chunks[0].PlaintextSize {
		t.Fatalf("destination received %d bytes, declared maximum is %d", destination.Len(), stream.Chunks[0].PlaintextSize)
	}
}

func mustMaterialIdentity(t *testing.T) MaterialIdentity {
	t.Helper()
	identity, err := GenerateMaterialIdentity()
	if err != nil {
		t.Fatalf("GenerateMaterialIdentity: %v", err)
	}
	return identity
}

type storedObject struct {
	descriptor Descriptor
	data       []byte
}

type memoryObjects struct {
	objects map[digest.Digest]storedObject
}

func newMemoryObjects() *memoryObjects {
	return &memoryObjects{objects: make(map[digest.Digest]storedObject)}
}

func (m *memoryObjects) Ingest(ctx context.Context, mediaType string, source io.Reader) (Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return Descriptor{}, err
	}
	data, err := io.ReadAll(source)
	if err != nil {
		return Descriptor{}, err
	}
	descriptor := Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	m.objects[descriptor.Digest] = storedObject{descriptor: descriptor, data: append([]byte(nil), data...)}
	return descriptor, nil
}

func (m *memoryObjects) Open(ctx context.Context, objectDigest digest.Digest) (io.ReadCloser, Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, Descriptor{}, err
	}
	object, exists := m.objects[objectDigest]
	if !exists {
		return nil, Descriptor{}, errors.New("object not found")
	}
	return io.NopCloser(bytes.NewReader(object.data)), object.descriptor, nil
}

func (m *memoryObjects) clone() *memoryObjects {
	clone := newMemoryObjects()
	for objectDigest, object := range m.objects {
		object.data = append([]byte(nil), object.data...)
		clone.objects[objectDigest] = object
	}
	return clone
}

type errorSink struct{ err error }

func (s errorSink) Ingest(context.Context, string, io.Reader) (Descriptor, error) {
	return Descriptor{}, s.err
}

type errorSource struct{ err error }

func (s errorSource) Open(context.Context, digest.Digest) (io.ReadCloser, Descriptor, error) {
	return nil, Descriptor{}, s.err
}

type mutatingDescriptorSink struct{ sink ObjectSink }

func (s mutatingDescriptorSink) Ingest(ctx context.Context, mediaType string, source io.Reader) (Descriptor, error) {
	descriptor, err := s.sink.Ingest(ctx, mediaType, source)
	if err == nil {
		descriptor.Size++
	}
	return descriptor, err
}

type mutatingDescriptorSource struct{ source ObjectSource }

func (s mutatingDescriptorSource) Open(ctx context.Context, objectDigest digest.Digest) (io.ReadCloser, Descriptor, error) {
	reader, descriptor, err := s.source.Open(ctx, objectDigest)
	if err == nil {
		descriptor.Size++
	}
	return reader, descriptor, err
}

type errorReader struct {
	data []byte
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, r.err
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type boundedRequestReader struct {
	reader       io.Reader
	limit        int
	maxRequested int
}

func (r *boundedRequestReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRequested {
		r.maxRequested = len(p)
	}
	if len(p) > r.limit {
		return 0, errors.New("oversized read request")
	}
	return r.reader.Read(p)
}

package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"

	"filippo.io/age"
	"github.com/opencontainers/go-digest"
)

const (
	DefaultPlaintextChunkSize = 4 * 1024 * 1024
	streamCopyBufferSize      = 32 * 1024
	maxConsecutiveEmptyReads  = 100
	unknownExpectedObjectSize = -1
)

// EncryptStream reads one complete plaintext stream, splits it into bounded
// chunks, and ingests independently authenticated age ciphertext objects.
// The returned digest and size describe the original stream, not its chunks.
func EncryptStream(
	ctx context.Context,
	sink ObjectSink,
	identity MaterialIdentity,
	plaintext io.Reader,
) (EncryptedStream, error) {
	return encryptStream(ctx, sink, identity, plaintext, DefaultPlaintextChunkSize)
}

func encryptStream(
	ctx context.Context,
	sink ObjectSink,
	identity MaterialIdentity,
	plaintext io.Reader,
	chunkSize int,
) (EncryptedStream, error) {
	if sink == nil {
		return EncryptedStream{}, errors.New("artifact: nil object sink")
	}
	if plaintext == nil {
		return EncryptedStream{}, errors.New("artifact: nil plaintext reader")
	}
	if chunkSize <= 0 {
		return EncryptedStream{}, fmt.Errorf("%w: chunk size must be positive", ErrInvalidArtifact)
	}
	recipient, err := identity.recipient()
	if err != nil {
		return EncryptedStream{}, err
	}

	buffer := make([]byte, chunkSize)
	defer clearBytes(buffer)
	plaintextHash := sha256.New()
	stream := EncryptedStream{Chunks: make([]ChunkRef, 0, 1)}
	first := true

	for {
		n, readErr := readChunk(ctx, plaintext, buffer)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return EncryptedStream{}, fmt.Errorf("read plaintext stream: %w", readErr)
		}
		if n == 0 && !first {
			break
		}
		if stream.Size > math.MaxInt64-int64(n) {
			return EncryptedStream{}, fmt.Errorf("%w: plaintext stream is too large", ErrInvalidArtifact)
		}
		if len(stream.Chunks) == MaxChunksPerStream {
			return EncryptedStream{}, fmt.Errorf("%w: stream exceeds %d chunks", ErrInvalidArtifact, MaxChunksPerStream)
		}

		chunk := buffer[:n]
		if _, err := plaintextHash.Write(chunk); err != nil {
			return EncryptedStream{}, fmt.Errorf("hash plaintext stream: %w", err)
		}
		descriptor, err := ingestAgeObject(
			ctx,
			sink,
			MediaTypeEncryptedChunk,
			recipient,
			bytes.NewReader(chunk),
		)
		if err != nil {
			return EncryptedStream{}, fmt.Errorf("encrypt chunk at offset %d: %w", stream.Size, err)
		}
		stream.Chunks = append(stream.Chunks, ChunkRef{
			Offset:        stream.Size,
			PlaintextSize: int64(n),
			Ciphertext:    descriptor,
		})
		stream.Size += int64(n)
		first = false

		if errors.Is(readErr, io.EOF) || n < chunkSize {
			break
		}
	}

	stream.Digest = digest.NewDigest(digest.SHA256, plaintextHash)
	if err := stream.Validate(); err != nil {
		return EncryptedStream{}, err
	}
	return stream, nil
}

// DecryptStream authenticates every age chunk, verifies ciphertext and
// plaintext digest/size, and writes the plaintext in stream order. Callers
// that materialize files must provide a private temporary destination and only
// publish it after this function returns nil.
func DecryptStream(
	ctx context.Context,
	source ObjectSource,
	identity MaterialIdentity,
	stream EncryptedStream,
	destination io.Writer,
) error {
	if source == nil {
		return errors.New("artifact: nil object source")
	}
	if destination == nil {
		return errors.New("artifact: nil plaintext destination")
	}
	if err := stream.Validate(); err != nil {
		return err
	}
	ageIdentity, err := identity.identity()
	if err != nil {
		return err
	}

	plaintextHash := sha256.New()
	streamWriter := io.MultiWriter(destination, plaintextHash)
	var plaintextSize int64
	canonical := canonicalEncryptedStream(stream)
	for i, chunk := range canonical.Chunks {
		chunkWriter := &maximumWriter{
			destination: streamWriter,
			remaining:   chunk.PlaintextSize,
		}
		written, err := decryptAgeObject(
			ctx,
			source,
			chunk.Ciphertext.Digest,
			MediaTypeEncryptedChunk,
			chunk.Ciphertext.Size,
			ageIdentity,
			chunkWriter,
		)
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", i, err)
		}
		if written != chunk.PlaintextSize {
			return fmt.Errorf("%w: chunk %d plaintext size is %d, want %d", ErrMaterialMismatch, i, written, chunk.PlaintextSize)
		}
		plaintextSize += written
	}
	if plaintextSize != stream.Size {
		return fmt.Errorf("%w: plaintext size is %d, want %d", ErrMaterialMismatch, plaintextSize, stream.Size)
	}
	if actual := digest.NewDigest(digest.SHA256, plaintextHash); actual != stream.Digest {
		return fmt.Errorf("%w: plaintext digest is %s, want %s", ErrMaterialMismatch, actual, stream.Digest)
	}
	return nil
}

type ageEncryptResult struct {
	descriptor Descriptor
	err        error
}

func ingestAgeObject(
	ctx context.Context,
	sink ObjectSink,
	mediaType string,
	recipient age.Recipient,
	plaintext io.Reader,
) (Descriptor, error) {
	pipeReader, pipeWriter := io.Pipe()
	result := make(chan ageEncryptResult, 1)
	go func() {
		observer := &observedWriter{
			destination: &contextWriter{ctx: ctx, destination: pipeWriter},
			hash:        sha256.New(),
		}
		ageWriter, err := age.Encrypt(observer, recipient)
		if err == nil {
			_, err = copyContext(ctx, ageWriter, plaintext)
		}
		if closeErr := closeIfNotNil(ageWriter); err == nil {
			err = closeErr
		}
		observed := Descriptor{
			MediaType: mediaType,
			Digest:    digest.NewDigest(digest.SHA256, observer.hash),
			Size:      observer.size,
		}
		result <- ageEncryptResult{descriptor: observed, err: err}
		_ = pipeWriter.CloseWithError(err)
	}()

	stored, sinkErr := sink.Ingest(ctx, mediaType, pipeReader)
	if sinkErr != nil {
		_ = pipeReader.CloseWithError(sinkErr)
	} else {
		_ = pipeReader.Close()
	}
	encrypted := <-result
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Descriptor{}, ctxErr
	}
	if encrypted.err != nil {
		return Descriptor{}, fmt.Errorf("encrypt age object: %w", encrypted.err)
	}
	if sinkErr != nil {
		return Descriptor{}, fmt.Errorf("ingest encrypted object: %w", sinkErr)
	}
	if err := stored.Validate(); err != nil {
		return Descriptor{}, fmt.Errorf("ingest returned invalid descriptor: %w", err)
	}
	if stored != encrypted.descriptor {
		return Descriptor{}, fmt.Errorf("%w: ingested descriptor does not match ciphertext", ErrMaterialMismatch)
	}
	return stored, nil
}

func decryptAgeObject(
	ctx context.Context,
	source ObjectSource,
	expectedDigest digest.Digest,
	expectedMediaType string,
	expectedSize int64,
	identity age.Identity,
	destination io.Writer,
) (written int64, returnedErr error) {
	object, descriptor, err := source.Open(ctx, expectedDigest)
	if err != nil {
		return 0, fmt.Errorf("open encrypted object: %w", err)
	}
	if object == nil {
		return 0, errors.New("artifact: object source returned a nil reader")
	}
	defer func() {
		if closeErr := object.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close encrypted object: %w", closeErr)
		}
	}()
	if err := descriptor.Validate(); err != nil {
		return 0, fmt.Errorf("object source returned invalid descriptor: %w", err)
	}
	if descriptor.Digest != expectedDigest {
		return 0, fmt.Errorf("%w: opened digest is %s, want %s", ErrMaterialMismatch, descriptor.Digest, expectedDigest)
	}
	if descriptor.MediaType != expectedMediaType {
		return 0, fmt.Errorf("%w: opened media type is %q, want %q", ErrMaterialMismatch, descriptor.MediaType, expectedMediaType)
	}
	if expectedSize >= 0 && descriptor.Size != expectedSize {
		return 0, fmt.Errorf("%w: opened ciphertext size is %d, want %d", ErrMaterialMismatch, descriptor.Size, expectedSize)
	}

	verified := &observedReader{
		source: &contextReader{ctx: ctx, source: object},
		hash:   sha256.New(),
	}
	plaintext, err := age.Decrypt(verified, identity)
	if err != nil {
		return 0, fmt.Errorf("decrypt age object: %w", err)
	}
	written, err = copyContext(ctx, destination, plaintext)
	if err != nil {
		return written, fmt.Errorf("read authenticated plaintext: %w", err)
	}
	if verified.size != descriptor.Size {
		return written, fmt.Errorf("%w: ciphertext size is %d, want %d", ErrMaterialMismatch, verified.size, descriptor.Size)
	}
	if actual := digest.NewDigest(digest.SHA256, verified.hash); actual != descriptor.Digest {
		return written, fmt.Errorf("%w: ciphertext digest is %s, want %s", ErrMaterialMismatch, actual, descriptor.Digest)
	}
	return written, nil
}

func readChunk(ctx context.Context, source io.Reader, buffer []byte) (int, error) {
	read := 0
	emptyReads := 0
	for read < len(buffer) {
		if err := ctx.Err(); err != nil {
			return read, err
		}
		n, err := source.Read(buffer[read:])
		if n < 0 || n > len(buffer)-read {
			return read, errors.New("artifact: invalid Reader count")
		}
		read += n
		if n == 0 && err == nil {
			emptyReads++
			if emptyReads >= maxConsecutiveEmptyReads {
				return read, io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, streamCopyBufferSize)
	defer clearBytes(buffer)
	var written int64
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n, readErr := source.Read(buffer)
		if n < 0 || n > len(buffer) {
			return written, errors.New("artifact: invalid Reader count")
		}
		if n > 0 {
			emptyReads = 0
			writeN, writeErr := destination.Write(buffer[:n])
			if writeN < 0 || writeN > n {
				return written, errors.New("artifact: invalid Writer count")
			}
			written += int64(writeN)
			if writeErr != nil {
				return written, writeErr
			}
			if writeN != n {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= maxConsecutiveEmptyReads {
				return written, io.ErrNoProgress
			}
		}
	}
}

func closeIfNotNil(closer io.WriteCloser) error {
	if closer == nil {
		return nil
	}
	return closer.Close()
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

type contextWriter struct {
	ctx         context.Context
	destination io.Writer
}

type maximumWriter struct {
	destination io.Writer
	remaining   int64
}

func (w *maximumWriter) Write(p []byte) (int, error) {
	if int64(len(p)) <= w.remaining {
		n, err := w.destination.Write(p)
		w.remaining -= int64(n)
		return n, err
	}

	allowed := int(w.remaining)
	written := 0
	if allowed > 0 {
		n, err := w.destination.Write(p[:allowed])
		written = n
		w.remaining -= int64(n)
		if err != nil {
			return written, err
		}
		if n != allowed {
			return written, io.ErrShortWrite
		}
	}
	return written, fmt.Errorf("%w: plaintext exceeds declared chunk size", ErrMaterialMismatch)
}

func (w *contextWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	return w.destination.Write(p)
}

type observedWriter struct {
	destination io.Writer
	hash        hash.Hash
	size        int64
}

func (w *observedWriter) Write(p []byte) (int, error) {
	n, err := w.destination.Write(p)
	if n > 0 {
		_, _ = w.hash.Write(p[:n])
		w.size += int64(n)
	}
	return n, err
}

type observedReader struct {
	source io.Reader
	hash   hash.Hash
	size   int64
}

func (r *observedReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
		r.size += int64(n)
	}
	return n, err
}

// Package cas provides an immutable, streaming filesystem content-addressed
// store. A descriptor sidecar is the visibility point for each object.
package cas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const (
	maxDescriptorBytes = 16 * 1024
	copyBufferSize     = 128 * 1024
)

var (
	// ErrNotFound means that no descriptor visibility point exists for an
	// object.
	ErrNotFound = errors.New("cas: object not found")
	// ErrCorrupt means that visible local CAS state does not match its immutable
	// descriptor.
	ErrCorrupt = errors.New("cas: corrupt object")
	// ErrConflict means that the digest already has a different descriptor.
	ErrConflict = errors.New("cas: descriptor conflict")
	// ErrUnsafePath means that a managed path is a symlink, special file, or
	// escapes the store root.
	ErrUnsafePath = errors.New("cas: unsafe path")
	// ErrUnsupportedAtomicPublish means the filesystem or operating system
	// cannot provide an atomic no-replace publish operation.
	ErrUnsupportedAtomicPublish = errors.New("cas: atomic no-replace publish is unsupported")
)

type publishFunc func(root *os.Root, source, destination string) (bool, error)

// Store is an immutable filesystem CAS. Store is safe for concurrent use.
type Store struct {
	root    string
	fs      *os.Root
	publish publishFunc
}

var (
	_ artifact.ObjectSink   = (*Store)(nil)
	_ artifact.ObjectSource = (*Store)(nil)
)

// New initializes a filesystem CAS rooted at rootPath. Existing managed paths
// must be real directories; symlinks and non-directories are rejected.
func New(rootPath string) (*Store, error) {
	if rootPath == "" {
		return nil, fmt.Errorf("%w: empty store root", ErrUnsafePath)
	}
	absolute, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("resolve CAS root: %w", err)
	}
	absolute = filepath.Clean(absolute)
	absolute, err = canonicalRootPath(absolute)
	if err != nil {
		return nil, err
	}
	if err := prepareRoot(absolute); err != nil {
		return nil, err
	}
	managedRoot, err := openManagedRoot(absolute)
	if err != nil {
		return nil, err
	}
	store := &Store{root: absolute, fs: managedRoot, publish: publishNoReplace}
	if err := store.protectManagedPath(absolute, true); err != nil {
		_ = managedRoot.Close()
		return nil, fmt.Errorf("protect CAS root handle: %w", err)
	}
	if err := store.ensureBaseLayout(); err != nil {
		_ = managedRoot.Close()
		return nil, err
	}
	return store, nil
}

// Ingest streams source into private temporary storage, computes its SHA-256
// digest and size, and atomically publishes an immutable object. The descriptor
// sidecar is published last and is the sole visibility point.
func (s *Store) Ingest(ctx context.Context, mediaType string, source io.Reader) (artifact.Descriptor, error) {
	if err := s.validateInitialized(); err != nil {
		return artifact.Descriptor{}, err
	}
	if ctx == nil {
		return artifact.Descriptor{}, errors.New("cas: nil context")
	}
	if source == nil {
		return artifact.Descriptor{}, errors.New("cas: nil ingest source")
	}
	if err := validateMediaType(mediaType); err != nil {
		return artifact.Descriptor{}, err
	}
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	if err := s.ensureBaseLayout(); err != nil {
		return artifact.Descriptor{}, err
	}

	temporary, temporaryName, err := s.createManagedTemp("ingest-data-")
	if err != nil {
		return artifact.Descriptor{}, fmt.Errorf("create private ingest file: %w", err)
	}
	defer func() {
		_ = temporary.Close()
		_ = s.fs.Remove(temporaryName)
	}()

	hasher := sha256.New()
	size, err := copyWithContext(ctx, io.MultiWriter(temporary, hasher), source)
	if err != nil {
		return artifact.Descriptor{}, fmt.Errorf("stream object into CAS: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	descriptor := artifact.Descriptor{
		MediaType: mediaType,
		Digest:    digest.NewDigest(digest.SHA256, hasher),
		Size:      size,
	}
	if err := descriptor.Validate(); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("validate ingested descriptor: %w", err)
	}

	if err := sealTemporaryFile(temporary); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("sync private ingest file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("close private ingest file: %w", err)
	}

	dataPath, descriptorPath, err := s.objectPaths(descriptor.Digest)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	if err := s.ensureObjectDirectories(dataPath, descriptorPath); err != nil {
		return artifact.Descriptor{}, err
	}

	dataName, err := s.managedName(dataPath)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	published, err := s.publish(s.fs, temporaryName, dataName)
	if err != nil {
		return artifact.Descriptor{}, fmt.Errorf("publish immutable object data: %w", err)
	}
	if !published {
		if err := s.verifyData(ctx, dataPath, descriptor); err != nil {
			return artifact.Descriptor{}, fmt.Errorf("verify concurrent object data: %w", err)
		}
	}
	if err := s.syncManagedDirectory(filepath.Dir(dataPath)); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("sync object directory: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}

	encoded, err := encodeDescriptor(descriptor)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	descriptorTemporary, descriptorTemporaryName, err := s.createManagedTemp("ingest-descriptor-")
	if err != nil {
		return artifact.Descriptor{}, fmt.Errorf("create private descriptor file: %w", err)
	}
	defer func() {
		_ = descriptorTemporary.Close()
		_ = s.fs.Remove(descriptorTemporaryName)
	}()
	if _, err := descriptorTemporary.Write(encoded); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("write descriptor sidecar: %w", err)
	}
	if err := sealTemporaryFile(descriptorTemporary); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("sync descriptor sidecar: %w", err)
	}
	if err := descriptorTemporary.Close(); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("close descriptor sidecar: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}

	descriptorName, err := s.managedName(descriptorPath)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	descriptorPublished, err := s.publish(s.fs, descriptorTemporaryName, descriptorName)
	if err != nil {
		return artifact.Descriptor{}, fmt.Errorf("publish descriptor visibility point: %w", err)
	}
	if err := s.syncManagedDirectory(filepath.Dir(descriptorPath)); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("sync descriptor directory: %w", err)
	}
	existing, exists, err := s.loadDescriptor(ctx, descriptor.Digest)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	if !exists {
		return artifact.Descriptor{}, fmt.Errorf("%w: published descriptor disappeared", ErrCorrupt)
	}
	if existing != descriptor {
		if descriptorPublished {
			return artifact.Descriptor{}, fmt.Errorf("%w: published descriptor changed", ErrCorrupt)
		}
		return artifact.Descriptor{}, fmt.Errorf("%w: digest %s is already bound to media type %q and size %d", ErrConflict, descriptor.Digest, existing.MediaType, existing.Size)
	}
	return descriptor, nil
}

// Open opens a visible object by digest. The returned stream verifies size and
// digest as it is consumed and reports corruption no later than the final byte.
func (s *Store) Open(ctx context.Context, objectDigest digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	if err := s.validateInitialized(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	if ctx == nil {
		return nil, artifact.Descriptor{}, errors.New("cas: nil context")
	}
	if err := validateDigest(objectDigest); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	descriptor, exists, err := s.loadDescriptor(ctx, objectDigest)
	if err != nil {
		return nil, artifact.Descriptor{}, err
	}
	if !exists {
		return nil, artifact.Descriptor{}, fmt.Errorf("%w: %s", ErrNotFound, objectDigest)
	}
	dataPath, _, err := s.objectPaths(objectDigest)
	if err != nil {
		return nil, artifact.Descriptor{}, err
	}
	reader, err := s.openVerifiedData(ctx, dataPath, descriptor)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, artifact.Descriptor{}, fmt.Errorf("%w: descriptor exists without data for %s", ErrCorrupt, objectDigest)
		}
		return nil, artifact.Descriptor{}, err
	}
	return reader, descriptor, nil
}

func (s *Store) validateInitialized() error {
	if s == nil || s.root == "" || !filepath.IsAbs(s.root) || s.fs == nil || s.publish == nil {
		return errors.New("cas: store must be initialized with New")
	}
	return nil
}

// Has reports whether a visible, fully verified object exists. Orphan data and
// temporary files are invisible. Visible corruption is returned as an error.
func (s *Store) Has(ctx context.Context, objectDigest digest.Digest) (bool, error) {
	reader, _, err := s.Open(ctx, objectDigest)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	buffer := make([]byte, copyBufferSize)
	if _, err := io.CopyBuffer(io.Discard, reader, buffer); err != nil {
		_ = reader.Close()
		return false, err
	}
	if err := reader.Close(); err != nil {
		return false, fmt.Errorf("close verified CAS object: %w", err)
	}
	return true, nil
}

func (s *Store) verifyData(ctx context.Context, path string, descriptor artifact.Descriptor) error {
	reader, err := s.openVerifiedData(ctx, path, descriptor)
	if err != nil {
		return err
	}
	buffer := make([]byte, copyBufferSize)
	_, copyErr := io.CopyBuffer(io.Discard, reader, buffer)
	closeErr := reader.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}

func (s *Store) openVerifiedData(ctx context.Context, path string, descriptor artifact.Descriptor) (io.ReadCloser, error) {
	file, info, err := s.openManagedRegular(path)
	if err != nil {
		return nil, err
	}
	if info.Size() != descriptor.Size {
		_ = file.Close()
		return nil, fmt.Errorf("%w: object size is %d, descriptor records %d", ErrCorrupt, info.Size(), descriptor.Size)
	}
	return &verifiedReadCloser{
		ctx:         ctx,
		file:        file,
		hash:        sha256.New(),
		expected:    descriptor.Digest,
		expectedN:   descriptor.Size,
		initialSize: info.Size(),
	}, nil
}

func encodeDescriptor(descriptor artifact.Descriptor) ([]byte, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("validate descriptor sidecar: %w", err)
	}
	encoded, err := artifact.MarshalCanonical(descriptor)
	if err != nil {
		return nil, fmt.Errorf("encode descriptor sidecar: %w", err)
	}
	if len(encoded) > maxDescriptorBytes {
		return nil, fmt.Errorf("cas: descriptor sidecar exceeds %d bytes", maxDescriptorBytes)
	}
	return encoded, nil
}

func decodeDescriptor(encoded []byte) (artifact.Descriptor, error) {
	if len(encoded) == 0 || len(encoded) > maxDescriptorBytes {
		return artifact.Descriptor{}, fmt.Errorf("%w: invalid descriptor sidecar size", ErrCorrupt)
	}
	var descriptor artifact.Descriptor
	if err := artifact.UnmarshalStrict(encoded, &descriptor); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("%w: decode descriptor sidecar: %v", ErrCorrupt, err)
	}
	canonical, err := encodeDescriptor(descriptor)
	if err != nil {
		return artifact.Descriptor{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if !bytes.Equal(encoded, canonical) {
		return artifact.Descriptor{}, fmt.Errorf("%w: non-canonical descriptor sidecar", ErrCorrupt)
	}
	return descriptor, nil
}

func validateMediaType(mediaType string) error {
	if mediaType == "" {
		return errors.New("cas: empty media type")
	}
	if _, _, err := mime.ParseMediaType(mediaType); err != nil {
		return fmt.Errorf("cas: invalid media type: %w", err)
	}
	if len(mediaType) > maxDescriptorBytes/2 {
		return fmt.Errorf("cas: media type exceeds %d bytes", maxDescriptorBytes/2)
	}
	return nil
}

func validateDigest(value digest.Digest) error {
	if err := value.Validate(); err != nil {
		return fmt.Errorf("cas: invalid digest: %w", err)
	}
	if value.Algorithm() != digest.SHA256 {
		return fmt.Errorf("cas: digest algorithm %q is not sha256", value.Algorithm())
	}
	return nil
}

func sealTemporaryFile(file *os.File) error {
	if err := file.Chmod(0o400); err != nil {
		return err
	}
	return file.Sync()
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, copyBufferSize)
	return io.CopyBuffer(destination, &contextReader{ctx: ctx, source: source}, buffer)
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(destination []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.source.Read(destination)
	if contextErr := r.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}

type verifiedReadCloser struct {
	ctx         context.Context
	file        *os.File
	hash        hash.Hash
	expected    digest.Digest
	expectedN   int64
	initialSize int64
	read        int64
	verified    bool
}

func (r *verifiedReadCloser) Read(destination []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, readErr := r.file.Read(destination)
	if n > 0 {
		_, _ = r.hash.Write(destination[:n])
		r.read += int64(n)
		if r.read > r.expectedN {
			return n, fmt.Errorf("%w: object grew beyond descriptor size", ErrCorrupt)
		}
		if r.read == r.expectedN {
			actual := digest.NewDigest(digest.SHA256, r.hash)
			if actual != r.expected {
				return n, fmt.Errorf("%w: object digest is %s, want %s", ErrCorrupt, actual, r.expected)
			}
			info, err := r.file.Stat()
			if err != nil {
				return n, fmt.Errorf("stat opened CAS object: %w", err)
			}
			if !info.Mode().IsRegular() || info.Size() != r.initialSize {
				return n, fmt.Errorf("%w: object changed while being read", ErrCorrupt)
			}
			r.verified = true
		}
	}
	if readErr == io.EOF && !r.verified {
		if r.read != r.expectedN {
			return n, fmt.Errorf("%w: object ended at %d bytes, want %d", ErrCorrupt, r.read, r.expectedN)
		}
		actual := digest.NewDigest(digest.SHA256, r.hash)
		if actual != r.expected {
			return n, fmt.Errorf("%w: object digest is %s, want %s", ErrCorrupt, actual, r.expected)
		}
		r.verified = true
	}
	if contextErr := r.ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, readErr
}

func (r *verifiedReadCloser) Close() error {
	return r.file.Close()
}

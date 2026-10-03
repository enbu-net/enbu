package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

const registryCopyBufferSize = 32 * 1024

const MaxPublicationObjects = 100_000

// PublicationClosure is the complete immutable object closure retained by one
// Commit announcement. Typed tiers make upload order explicit and prevent a
// caller from accidentally publishing Grants before their ciphertext.
type PublicationClosure struct {
	PayloadChunks     []artifact.Descriptor
	MaterialManifests []artifact.Descriptor
	AccessGrants      []artifact.Descriptor
	PluginPackages    []artifact.Descriptor
}

// Publish uploads a complete immutable closure in dependency order and makes
// it visible only by publishing the content-derived announcement tag last.
func Publish(
	ctx context.Context,
	remote Remote,
	local artifact.ObjectSource,
	closure PublicationClosure,
	announcement CommitAnnouncement,
) (artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	if remote == nil || local == nil {
		return artifact.Descriptor{}, errors.New("registry: nil remote or local source")
	}
	if err := announcement.Validate(); err != nil {
		return artifact.Descriptor{}, err
	}

	ordered, err := canonicalPublicationClosure(closure, announcement.Grant, announcement.EncryptedCommit)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	for _, descriptor := range ordered {
		if err := ensureRemoteObject(ctx, remote, local, descriptor); err != nil {
			return artifact.Descriptor{}, fmt.Errorf("publish dependency %s: %w", descriptor.Digest, err)
		}
	}
	if err := ensureRemoteObject(ctx, remote, local, announcement.EncryptedCommit); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("publish encrypted Commit: %w", err)
	}

	encoded, err := EncodeCommitAnnouncement(announcement)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	announcementDescriptor := artifact.Descriptor{
		MediaType: artifact.MediaTypeCommitAnnouncement,
		Digest:    digest.FromBytes(encoded),
		Size:      int64(len(encoded)),
	}
	if err := ensureRemoteBytes(ctx, remote, announcementDescriptor, encoded); err != nil {
		return artifact.Descriptor{}, fmt.Errorf("publish announcement object: %w", err)
	}
	tag, err := AnnouncementTag(announcementDescriptor.Digest)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	retained := append(append([]artifact.Descriptor(nil), ordered...), announcement.EncryptedCommit)
	if err := remote.PublishAnnouncement(ctx, tag, announcementDescriptor, retained); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return artifact.Descriptor{}, ctxErr
		}
		return artifact.Descriptor{}, fmt.Errorf("publish announcement visibility point: %w", err)
	}
	return announcementDescriptor, nil
}

func canonicalPublicationClosure(
	closure PublicationClosure,
	grant artifact.Descriptor,
	commit artifact.Descriptor,
) ([]artifact.Descriptor, error) {
	type tier struct {
		mediaType   string
		descriptors []artifact.Descriptor
	}
	tiers := []tier{
		{mediaType: artifact.MediaTypeEncryptedChunk, descriptors: closure.PayloadChunks},
		{mediaType: artifact.MediaTypeEncryptedMaterial, descriptors: closure.MaterialManifests},
		{mediaType: artifact.MediaTypeAccessGrant, descriptors: append(append([]artifact.Descriptor(nil), closure.AccessGrants...), grant)},
		{mediaType: artifact.MediaTypePluginPackage, descriptors: closure.PluginPackages},
	}
	total := 1
	for _, current := range tiers {
		if len(current.descriptors) > MaxPublicationObjects-total {
			return nil, fmt.Errorf("%w: publication closure exceeds %d objects", ErrInvalidRemoteObject, MaxPublicationObjects)
		}
		total += len(current.descriptors)
	}

	seen := make(map[digest.Digest]artifact.Descriptor, total)
	ordered := make([]artifact.Descriptor, 0, total)
	for _, current := range tiers {
		canonical := append([]artifact.Descriptor(nil), current.descriptors...)
		sort.Slice(canonical, func(i, j int) bool { return canonical[i].Digest < canonical[j].Digest })
		for _, descriptor := range canonical {
			if err := validateDescriptor(descriptor, current.mediaType); err != nil {
				return nil, err
			}
			if descriptor.Digest == commit.Digest {
				if descriptor != commit {
					return nil, fmt.Errorf("%w: Commit digest has conflicting descriptor", ErrInvalidRemoteObject)
				}
				return nil, fmt.Errorf("%w: encrypted Commit must not appear in dependency closure", ErrInvalidRemoteObject)
			}
			if existing, ok := seen[descriptor.Digest]; ok {
				if existing != descriptor {
					return nil, fmt.Errorf("%w: one digest has conflicting descriptors", ErrInvalidRemoteObject)
				}
				continue
			}
			seen[descriptor.Digest] = descriptor
			ordered = append(ordered, descriptor)
		}
	}
	return ordered, nil
}

func ensureRemoteObject(ctx context.Context, remote ObjectRemote, local artifact.ObjectSource, expected artifact.Descriptor) (returnedErr error) {
	if err := expected.Validate(); err != nil {
		return err
	}
	has, err := remote.Has(ctx, expected.Digest)
	if err != nil {
		return err
	}
	if has {
		return verifyRemoteObject(ctx, remote, expected)
	}

	reader, descriptor, err := local.Open(ctx, expected.Digest)
	if err != nil {
		return err
	}
	if reader == nil {
		return fmt.Errorf("%w: local source returned nil reader", ErrInvalidRemoteObject)
	}
	defer func() {
		if closeErr := reader.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close local object: %w", closeErr)
		}
	}()
	if descriptor != expected {
		return fmt.Errorf("%w: local descriptor mismatch", ErrInvalidRemoteObject)
	}
	observed := newObservedContextReader(ctx, reader, expected.Size)
	if err := remote.Push(ctx, expected, observed); err != nil {
		return err
	}
	if err := observed.complete(expected); err != nil {
		return fmt.Errorf("local source: %w", err)
	}
	return verifyRemoteObject(ctx, remote, expected)
}

func ensureRemoteBytes(ctx context.Context, remote ObjectRemote, expected artifact.Descriptor, data []byte) error {
	has, err := remote.Has(ctx, expected.Digest)
	if err != nil {
		return err
	}
	if !has {
		if err := remote.Push(ctx, expected, bytes.NewReader(data)); err != nil {
			return err
		}
	}
	return verifyRemoteObject(ctx, remote, expected)
}

func verifyRemoteObject(ctx context.Context, remote ObjectRemote, expected artifact.Descriptor) (returnedErr error) {
	reader, descriptor, err := openExpectedObject(ctx, remote, expected)
	if err != nil {
		return err
	}
	if reader == nil {
		return fmt.Errorf("%w: remote returned nil reader", ErrInvalidRemoteObject)
	}
	defer func() {
		if closeErr := reader.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close remote object: %w", closeErr)
		}
	}()
	if descriptor != expected {
		return fmt.Errorf("%w: descriptor mismatch", ErrInvalidRemoteObject)
	}
	observed := newObservedContextReader(ctx, reader, expected.Size)
	if _, err := io.CopyBuffer(io.Discard, observed, make([]byte, registryCopyBufferSize)); err != nil {
		return observed.classifyReadError(err)
	}
	if err := observed.complete(expected); err != nil {
		return err
	}
	return nil
}

func openExpectedObject(
	ctx context.Context,
	source artifact.ObjectSource,
	expected artifact.Descriptor,
) (io.ReadCloser, artifact.Descriptor, error) {
	if exact, ok := source.(artifact.ExpectedObjectSource); ok {
		reader, err := exact.OpenExpected(ctx, expected)
		return reader, expected, err
	}
	return source.Open(ctx, expected.Digest)
}

type observedContextReader struct {
	ctx           context.Context
	reader        io.Reader
	hash          hash.Hash
	size          int64
	maxSize       int64
	sawEOF        bool
	sourceErr     error
	validationErr error
}

func newObservedContextReader(ctx context.Context, reader io.Reader, maxSize int64) *observedContextReader {
	return &observedContextReader{ctx: ctx, reader: reader, hash: sha256.New(), maxSize: maxSize}
}

func (r *observedContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if n < 0 || n > len(p) {
		r.validationErr = fmt.Errorf("%w: invalid Reader count", ErrInvalidRemoteObject)
		return 0, r.validationErr
	}
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
		r.size += int64(n)
		if r.size > r.maxSize {
			r.validationErr = fmt.Errorf("%w: object exceeds declared size", ErrInvalidRemoteObject)
			return n, r.validationErr
		}
	}
	if errors.Is(err, io.EOF) {
		r.sawEOF = true
	} else if err != nil {
		r.sourceErr = err
	}
	return n, err
}

func (r *observedContextReader) complete(expected artifact.Descriptor) error {
	if r.validationErr != nil {
		return r.validationErr
	}
	if r.sourceErr != nil {
		return r.sourceErr
	}
	if r.size != expected.Size {
		return fmt.Errorf("%w: size is %d, want %d", ErrInvalidRemoteObject, r.size, expected.Size)
	}
	if actual := digest.NewDigest(digest.SHA256, r.hash); actual != expected.Digest {
		return fmt.Errorf("%w: digest is %s, want %s", ErrInvalidRemoteObject, actual, expected.Digest)
	}
	if !r.sawEOF {
		var probe [1]byte
		n, err := r.Read(probe[:])
		if r.validationErr != nil {
			return r.validationErr
		}
		if r.sourceErr != nil {
			return r.sourceErr
		}
		if n != 0 || !errors.Is(err, io.EOF) || !r.sawEOF {
			return fmt.Errorf("%w: source was not consumed through EOF", ErrInvalidRemoteObject)
		}
	}
	return nil
}

func (r *observedContextReader) classifyReadError(err error) error {
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if r.validationErr != nil {
		return r.validationErr
	}
	if r.sourceErr != nil {
		return r.sourceErr
	}
	return err
}

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

type ociStore struct {
	repo    *remote.Repository
	deleter TagDeleter
}

const (
	ociHeadMediaType   = "application/vnd.enbu.head.v1"
	ociBlobMediaType   = "application/vnd.enbu.blob.v1"
	ociConfigMediaType = "application/vnd.enbu.config.v1+json"
)

// NewOCI publishes each revision as one OCI manifest under a unique tag. No
// Referrers `subject` is set: GHCR has no native Referrers support and the
// specification would then require updating a racy fallback index.
func NewOCI(ref string, credential auth.CredentialFunc, plainHTTP bool, opts ...OCIOption) (Store, error) {
	r, err := remote.NewRepository(ref)
	if err != nil {
		return nil, err
	}
	if r.Reference.Reference != "" {
		return nil, errors.New("storage OCI URL must identify a repository without a tag or digest")
	}
	if credential == nil {
		store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
		if err != nil {
			return nil, err
		}
		credential = credentials.Credential(store)
	}
	r.Client = &auth.Client{Credential: credential, Cache: auth.NewCache()}
	r.PlainHTTP = plainHTTP
	s := ociStore{repo: r}
	for _, opt := range opts {
		opt(&s)
	}
	return s, nil
}

func remoteError(err error) error {
	if errors.Is(err, errdef.ErrNotFound) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

func (s ociStore) Capabilities() Capabilities { return Capabilities{PhysicalDelete: s.deleter != nil} }

// Delete removes the revision's package version through the registry
// provider. Without a provider's delete API a registry cannot do it.
func (s ociStore) Delete(ctx context.Context, kind Kind, scope string, rev digest.Digest) error {
	if s.deleter == nil {
		return ErrUnsupported
	}
	name, err := Name(kind, scope, rev)
	if err != nil {
		return err
	}
	return s.deleter.DeleteTag(ctx, name)
}

func blobDescriptor(mediaType string, data []byte) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
}

// manifestFor builds the canonical manifest of an object: no timestamps and a
// fixed layer order (the head, then the blobs), so publishing the same object
// twice is byte-identical.
func manifestFor(o Object) (cfg ocispec.Descriptor, layers []ocispec.Descriptor, body []byte, desc ocispec.Descriptor, err error) {
	cfg = blobDescriptor(ociConfigMediaType, []byte("{}"))
	layers = []ocispec.Descriptor{blobDescriptor(ociHeadMediaType, o.Head)}
	for _, b := range o.Blobs {
		layers = append(layers, blobDescriptor(ociBlobMediaType, b))
	}
	body, err = json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cfg, Layers: layers})
	desc = blobDescriptor(ocispec.MediaTypeImageManifest, body)
	return
}

func (s ociStore) pushBlob(ctx context.Context, desc ocispec.Descriptor, data []byte) error {
	blobs := s.repo.Blobs()
	exists, err := blobs.Exists(ctx, desc)
	if err != nil {
		return remoteError(err)
	}
	if exists {
		return nil
	}
	if err := blobs.Push(ctx, desc, bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return remoteError(err)
	}
	return nil
}

func (s ociStore) Publish(ctx context.Context, o Object) error {
	if err := ValidateObject(o); err != nil {
		return err
	}
	name, err := Name(o.Kind, o.Scope, o.Rev)
	if err != nil {
		return err
	}
	cfg, layers, body, md, err := manifestFor(o)
	if err != nil {
		return err
	}
	current, err := s.repo.Resolve(ctx, name)
	switch {
	case err == nil && current.Digest != md.Digest:
		return fmt.Errorf("%w: tag %s already points at different content", ErrCorrupt, name)
	case err != nil && !errors.Is(err, errdef.ErrNotFound):
		return remoteError(err)
	}
	if err != nil { // not published yet
		if err := s.pushBlob(ctx, cfg, []byte("{}")); err != nil {
			return err
		}
		for i, part := range append([][]byte{o.Head}, o.Blobs...) {
			if err := s.pushBlob(ctx, layers[i], part); err != nil {
				return err
			}
		}
		if err := s.repo.PushReference(ctx, md, bytes.NewReader(body), name); err != nil {
			return remoteError(err)
		}
	}
	// Acknowledge only after reading the tag back and checking that the registry
	// still holds every blob the manifest names (a registry GC may have dropped one).
	back, err := s.repo.Resolve(ctx, name)
	if err != nil {
		return remoteError(err)
	}
	if back.Digest != md.Digest {
		return fmt.Errorf("%w: tag %s changed while publishing", ErrCorrupt, name)
	}
	for _, l := range append([]ocispec.Descriptor{cfg}, layers...) {
		ok, err := s.repo.Blobs().Exists(ctx, l)
		if err != nil {
			return remoteError(err)
		}
		if !ok {
			return fmt.Errorf("%w: blob %s of %s is missing after publish", ErrNotFound, l.Digest, name)
		}
	}
	return nil
}

// fetchLimited reads a descriptor of at most limit bytes and checks its digest.
func fetchLimited(ctx context.Context, r *remote.Repository, d ocispec.Descriptor, limit int64) ([]byte, error) {
	if d.Size < 0 || d.Size > limit {
		return nil, ErrTooLarge
	}
	reader, err := r.Fetch(ctx, d)
	if err != nil {
		return nil, remoteError(err)
	}
	defer func() { _ = reader.Close() }()
	b, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != d.Size || digest.FromBytes(b) != d.Digest {
		return nil, fmt.Errorf("%w: OCI object size or digest mismatch", ErrCorrupt)
	}
	return b, nil
}

// manifest resolves the tag of an object and reads its manifest, checking that
// the first layer is the head the revision names.
func (s ociStore) manifest(ctx context.Context, kind Kind, scope string, rev digest.Digest) (ocispec.Manifest, string, error) {
	name, err := Name(kind, scope, rev)
	if err != nil {
		return ocispec.Manifest{}, "", err
	}
	desc, err := s.repo.Resolve(ctx, name)
	if err != nil {
		return ocispec.Manifest{}, "", remoteError(err)
	}
	raw, err := fetchLimited(ctx, s.repo, desc, MaxHeadBytes)
	if err != nil {
		return ocispec.Manifest{}, "", err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return ocispec.Manifest{}, "", fmt.Errorf("%w: manifest: %v", ErrCorrupt, err)
	}
	if len(m.Layers) == 0 || len(m.Layers) > MaxBlobs+1 || m.Layers[0].MediaType != ociHeadMediaType || m.Layers[0].Digest != rev {
		return ocispec.Manifest{}, "", fmt.Errorf("%w: manifest of %s does not match its name", ErrCorrupt, name)
	}
	return m, name, nil
}

func (s ociStore) FetchHead(ctx context.Context, kind Kind, scope string, rev digest.Digest) ([]byte, error) {
	m, _, err := s.manifest(ctx, kind, scope, rev)
	if err != nil {
		return nil, err
	}
	return fetchLimited(ctx, s.repo, m.Layers[0], MaxHeadBytes)
}

func (s ociStore) OpenBlob(ctx context.Context, kind Kind, scope string, rev digest.Digest, index int) (io.ReadCloser, error) {
	m, name, err := s.manifest(ctx, kind, scope, rev)
	if err != nil {
		return nil, err
	}
	if index < 0 || index+1 >= len(m.Layers) || m.Layers[index+1].MediaType != ociBlobMediaType {
		return nil, fmt.Errorf("%w: %s has no blob %d", ErrNotFound, name, index)
	}
	layer := m.Layers[index+1]
	if layer.Size < 0 || layer.Size > MaxPayloadBytes {
		return nil, ErrTooLarge
	}
	rc, err := s.repo.Fetch(ctx, layer)
	if err != nil {
		return nil, remoteError(err)
	}
	return newVerifyReader(rc, layer), nil
}

// verifyReader fails at the end unless the bytes are the layer the manifest names.
type verifyReader struct {
	rc   io.ReadCloser
	v    digest.Verifier
	want int64
	n    int64
	err  error
}

func newVerifyReader(rc io.ReadCloser, d ocispec.Descriptor) io.ReadCloser {
	return &verifyReader{rc: rc, v: d.Digest.Verifier(), want: d.Size}
}

func (r *verifyReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.rc.Read(p)
	r.n += int64(n)
	_, _ = r.v.Write(p[:n])
	if r.n > r.want {
		r.err = fmt.Errorf("%w: blob is larger than its layer", ErrCorrupt)
		return 0, r.err
	}
	if errors.Is(err, io.EOF) && (r.n != r.want || !r.v.Verified()) {
		r.err = fmt.Errorf("%w: blob does not match its layer", ErrCorrupt)
		return n, r.err
	}
	return n, err
}

func (r *verifyReader) Close() error { return r.rc.Close() }

// repositoryUnknown reports a registry's "name unknown" answer, which is how
// one that creates repositories on first push (zot, GHCR) answers a listing of
// a repository that has never been pushed to.
func repositoryUnknown(err error) bool {
	var resp *errcode.ErrorResponse
	return errors.As(err, &resp) && resp.StatusCode == http.StatusNotFound
}

func (s ociStore) Discover(ctx context.Context, kind Kind, scope string) ([]digest.Digest, error) {
	prefix, err := namePrefix(kind, scope)
	if err != nil {
		return nil, err
	}
	var revs []digest.Digest
	err = s.repo.Tags(ctx, "", func(tags []string) error {
		for _, tag := range tags {
			if rev, ok := revFromName(prefix, tag); ok && !strings.ContainsAny(tag, "/") {
				revs = append(revs, rev)
			}
		}
		return nil
	})
	if errors.Is(err, errdef.ErrNotFound) || repositoryUnknown(err) {
		return nil, nil // nothing was ever published here
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	return revs, remoteError(err)
}

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
	repo *remote.Repository
	// packages deletes revisions, which plain OCI cannot; nil for registries
	// other than ghcr.io.
	packages *GHCRPackages
}

const (
	ociHeadMediaType    = "application/vnd.enbu.head.v1"
	ociPayloadMediaType = "application/vnd.enbu.payload.v1"
	ociConfigMediaType  = "application/vnd.enbu.config.v1+json"
)

// NewOCI publishes each revision as one OCI manifest under a unique tag. No
// Referrers `subject` is set: GHCR has no native Referrers support and the
// specification would then require updating a racy fallback index.
func NewOCI(ref string, credential auth.CredentialFunc, plainHTTP bool) (Store, error) {
	return newOCI(ref, credential, plainHTTP)
}

// NewGHCR is NewOCI for ghcr.io, which also deletes revisions through the
// GitHub Packages API with token.
func NewGHCR(ref string, credential auth.CredentialFunc, token func() (string, error)) (Store, error) {
	s, err := newOCI(ref, credential, false)
	if err != nil {
		return nil, err
	}
	s.packages, _ = GHCRPackagesFor(ref, token)
	return s, nil
}

func newOCI(ref string, credential auth.CredentialFunc, plainHTTP bool) (ociStore, error) {
	r, err := remote.NewRepository(ref)
	if err != nil {
		return ociStore{}, err
	}
	if r.Reference.Reference != "" {
		return ociStore{}, errors.New("storage OCI URL must identify a repository without a tag or digest")
	}
	if credential == nil {
		store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
		if err != nil {
			return ociStore{}, err
		}
		credential = credentials.Credential(store)
	}
	r.Client = &auth.Client{Credential: credential, Cache: auth.NewCache()}
	r.PlainHTTP = plainHTTP
	return ociStore{repo: r}, nil
}

func remoteError(err error) error {
	if errors.Is(err, errdef.ErrNotFound) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

// Delete removes the revision's package version through the registry
// provider. Without a provider's delete API a registry cannot do it.
func (s ociStore) Delete(ctx context.Context, kind Kind, scope string, rev digest.Digest) error {
	if s.packages == nil {
		return ErrUnsupported
	}
	name, err := Name(kind, scope, rev)
	if err != nil {
		return err
	}
	return s.packages.DeleteTag(ctx, name)
}

func blobDescriptor(mediaType string, data []byte) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
}

// ociBlob is one blob a manifest names, with its content.
type ociBlob struct {
	desc ocispec.Descriptor
	data []byte
}

// maxOCILayers is the most layers a manifest has: the head and an optional payload.
const maxOCILayers = 2

// manifestFor builds the canonical manifest of an object: no timestamps and a
// fixed layer order (the head, then the payload), so publishing the same
// object twice is byte-identical. It returns every blob the manifest names.
func manifestFor(o Object) (blobs []ociBlob, body []byte, desc ocispec.Descriptor, err error) {
	blobs = []ociBlob{{blobDescriptor(ociConfigMediaType, []byte("{}")), []byte("{}")}, {blobDescriptor(ociHeadMediaType, o.Head), o.Head}}
	if len(o.Payload) > 0 {
		blobs = append(blobs, ociBlob{blobDescriptor(ociPayloadMediaType, o.Payload), o.Payload})
	}
	layers := make([]ocispec.Descriptor, 0, maxOCILayers)
	for _, b := range blobs[1:] {
		layers = append(layers, b.desc)
	}
	body, err = json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: blobs[0].desc, Layers: layers})
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

// publishAttempts bounds how often Publish uploads blobs again that the
// registry dropped before the manifest naming them was read back (a registry GC
// of blobs no manifest referenced yet).
const publishAttempts = 3

// errBlobGone is a blob missing from the registry after publishing.
var errBlobGone = errors.New("blob is missing after publish")

// blobUnknown reports a registry refusing a manifest because it lacks a blob
// the manifest names.
func blobUnknown(err error) bool {
	var resp *errcode.ErrorResponse
	if !errors.As(err, &resp) {
		return false
	}
	for _, e := range resp.Errors {
		if e.Code == errcode.ErrorCodeManifestBlobUnknown || e.Code == errcode.ErrorCodeBlobUnknown {
			return true
		}
	}
	return false
}

func (s ociStore) Publish(ctx context.Context, o Object) error {
	if err := ValidateObject(o); err != nil {
		return err
	}
	name, err := Name(o.Kind, o.Scope, o.Rev)
	if err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		err := s.publishOnce(ctx, name, o)
		if !errors.Is(err, errBlobGone) || attempt == publishAttempts {
			// Not ErrNotFound: the object was published, not looked up.
			return err
		}
	}
}

// publishOnce uploads the blobs the registry lacks and the manifest, unless
// the tag already names it, and acknowledges only after reading the tag back
// and checking that the registry holds every blob the manifest names.
func (s ociStore) publishOnce(ctx context.Context, name string, o Object) error {
	blobs, body, md, err := manifestFor(o)
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
	for _, b := range blobs {
		if err := s.pushBlob(ctx, b.desc, b.data); err != nil {
			return err
		}
	}
	if err != nil { // not published yet
		if err := s.repo.PushReference(ctx, md, bytes.NewReader(body), name); err != nil {
			if blobUnknown(err) {
				return fmt.Errorf("%w: %w", errBlobGone, err)
			}
			return remoteError(err)
		}
	}
	back, err := s.repo.Resolve(ctx, name)
	if err != nil {
		return remoteError(err)
	}
	if back.Digest != md.Digest {
		return fmt.Errorf("%w: tag %s changed while publishing", ErrCorrupt, name)
	}
	for _, b := range blobs {
		ok, err := s.repo.Blobs().Exists(ctx, b.desc)
		if err != nil {
			return remoteError(err)
		}
		if !ok {
			return fmt.Errorf("%w: %s of %s", errBlobGone, b.desc.Digest, name)
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
	if len(m.Layers) == 0 || len(m.Layers) > maxOCILayers || m.Layers[0].MediaType != ociHeadMediaType || m.Layers[0].Digest != rev {
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

func (s ociStore) OpenPayload(ctx context.Context, kind Kind, scope string, rev digest.Digest) (io.ReadCloser, error) {
	m, name, err := s.manifest(ctx, kind, scope, rev)
	if err != nil {
		return nil, err
	}
	if len(m.Layers) != maxOCILayers || m.Layers[1].MediaType != ociPayloadMediaType {
		return nil, fmt.Errorf("%w: %s has no payload", ErrNotFound, name)
	}
	layer := m.Layers[1]
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
		r.err = fmt.Errorf("%w: payload is larger than its layer", ErrCorrupt)
		return 0, r.err
	}
	if errors.Is(err, io.EOF) && (r.n != r.want || !r.v.Verified()) {
		r.err = fmt.Errorf("%w: payload does not match its layer", ErrCorrupt)
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
				if kind == KindRequest && len(revs) > MaxRequestRefs {
					return ErrDiscoveryLimit
				}
			}
		}
		return nil
	})
	if errors.Is(err, errdef.ErrNotFound) || repositoryUnknown(err) {
		return nil, nil // nothing was ever published here
	}
	if err != nil {
		return nil, remoteError(err)
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i] < revs[j] })
	return revs, remoteError(err)
}

func (s ociStore) Scopes(ctx context.Context) ([]string, error) {
	var names []string
	err := s.repo.Tags(ctx, "", func(tags []string) error {
		names = append(names, tags...)
		return nil
	})
	if errors.Is(err, errdef.ErrNotFound) || repositoryUnknown(err) {
		return nil, nil // nothing was ever published here
	}
	if err != nil {
		return nil, remoteError(err)
	}
	return sortedScopes(names), nil
}

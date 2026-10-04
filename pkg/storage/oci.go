package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

type ociRepo struct{ repo *remote.Repository }
type ociBlobs struct{ ociRepo }
type ociRefs struct{ ociRepo }

const (
	ociBlobMediaType   = "application/octet-stream"
	ociConfigMediaType = "application/vnd.enbu.config.v1+json"
)

func NewOCI(ref string, credential auth.CredentialFunc, plainHTTP bool) (*Store, error) {
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
	repo := ociRepo{r}
	return &Store{Blobs: ociBlobs{repo}, Refs: ociRefs{repo}}, nil
}

func remoteError(err error) error {
	if errors.Is(err, errdef.ErrNotFound) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

func (s ociBlobs) Put(ctx context.Context, src io.Reader) (digest.Digest, error) {
	f, err := spool(ctx, src)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	desc := ocispec.Descriptor{MediaType: ociBlobMediaType, Digest: f.Digest, Size: f.Size}
	return f.Digest, s.pushBlob(ctx, desc, f)
}

func (s ociRepo) pushBlob(ctx context.Context, desc ocispec.Descriptor, r io.Reader) error {
	blobs := s.repo.Blobs()
	exists, err := blobs.Exists(ctx, desc)
	if err != nil {
		return remoteError(err)
	}
	if exists {
		return nil
	}
	if err := blobs.Push(ctx, desc, r); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return remoteError(err)
	}
	return nil
}

func (s ociBlobs) Open(ctx context.Context, d digest.Digest) (io.ReadCloser, error) {
	if err := ValidateDigest(d); err != nil {
		return nil, err
	}
	desc, rc, err := s.repo.Blobs().FetchReference(ctx, d.String())
	if err != nil {
		return nil, remoteError(err)
	}
	if desc.Size < 0 || desc.Size > MaxPayloadBytes {
		_ = rc.Close()
		return nil, ErrTooLarge
	}
	return newVerifyReader(rc, d), nil
}

func (s ociRefs) Get(ctx context.Context, name string) (digest.Digest, Version, error) {
	if err := ValidateKey(name); err != nil {
		return "", "", err
	}
	desc, err := s.repo.Resolve(ctx, name)
	if err != nil {
		return "", "", remoteError(err)
	}
	b, err := fetchLimited(ctx, s.repo, desc, 1024*1024)
	if err != nil {
		return "", "", err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return "", "", err
	}
	if len(m.Layers) != 1 {
		return "", "", errors.New("enbu OCI manifest must have one layer")
	}
	if err := ValidateDigest(m.Layers[0].Digest); err != nil {
		return "", "", err
	}
	return m.Layers[0].Digest, Version(desc.Digest), nil
}

func fetchLimited(ctx context.Context, r *remote.Repository, d ocispec.Descriptor, limit int64) ([]byte, error) {
	if d.Size < 0 || d.Size > limit {
		return nil, errors.New("OCI object exceeds size limit")
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
		return nil, errors.New("OCI object size or digest mismatch")
	}
	return b, nil
}

// Put points the tag at a manifest whose only layer is the target blob, so the
// registry keeps the blob alive.
func (s ociRefs) Put(ctx context.Context, name string, target digest.Digest, expected Version) error {
	if err := ValidateKey(name); err != nil {
		return err
	}
	if err := ValidateDigest(target); err != nil {
		return err
	}
	layer, err := s.repo.Blobs().Resolve(ctx, target.String())
	if err != nil {
		return remoteError(err)
	}
	layer.MediaType = ociBlobMediaType
	config := ocispec.Descriptor{MediaType: ociConfigMediaType, Digest: digest.FromBytes([]byte("{}")), Size: 2}
	if err := s.pushBlob(ctx, config, strings.NewReader("{}")); err != nil {
		return err
	}
	b, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: config, Layers: []ocispec.Descriptor{layer}})
	if err != nil {
		return err
	}
	current, err := s.repo.Resolve(ctx, name)
	if err != nil && !errors.Is(err, errdef.ErrNotFound) {
		return remoteError(err)
	}
	if err == nil && Version(current.Digest) != expected || err != nil && expected != "" {
		return ErrConflict
	}
	// Distribution has no atomic conditional manifest PUT. This check is best effort.
	desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(b), Size: int64(len(b))}
	return remoteError(s.repo.PushReference(ctx, desc, bytes.NewReader(b), name))
}

func (s ociRefs) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	err := s.repo.Tags(ctx, "", func(tags []string) error {
		for _, key := range tags {
			if strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
		}
		return nil
	})
	if errors.Is(err, errdef.ErrNotFound) {
		return nil, nil
	}
	sort.Strings(keys)
	return keys, remoteError(err)
}

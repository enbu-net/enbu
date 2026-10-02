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
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

type OCI struct {
	Repository *remote.Repository
	SourceURL  string
}

func NewOCI(ref string, credential auth.CredentialFunc, plainHTTP bool) (*OCI, error) {
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
	return &OCI{Repository: r}, nil
}

func (s *OCI) Capabilities() Capabilities { return Capabilities{} }

func remoteError(err error) error {
	if errors.Is(err, errdef.ErrNotFound) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

func (s *OCI) Get(ctx context.Context, key string) (Object, Version, error) {
	if err := ValidateKey(key); err != nil {
		return Object{}, "", err
	}
	desc, err := s.Repository.Resolve(ctx, key)
	if err != nil {
		return Object{}, "", remoteError(err)
	}
	b, err := fetchLimited(ctx, s.Repository, desc, 1024*1024)
	if err != nil {
		return Object{}, "", err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Object{}, "", err
	}
	if len(m.Layers) != 1 {
		return Object{}, "", errors.New("enbu OCI manifest must have one layer")
	}
	data, err := fetchLimited(ctx, s.Repository, m.Layers[0], MaxPayloadBytes)
	if err != nil {
		return Object{}, "", err
	}
	o := Object{MediaType: m.Layers[0].MediaType, Data: data}
	if err := ValidateObject(o); err != nil {
		return Object{}, "", err
	}
	return o, Version(desc.Digest), nil
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

func (s *OCI) Put(ctx context.Context, key string, o Object, expected Version) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	if err := ValidateObject(o); err != nil {
		return err
	}
	store := memory.New()
	push := func(media string, b []byte) (ocispec.Descriptor, error) {
		d := ocispec.Descriptor{MediaType: media, Digest: digest.FromBytes(b), Size: int64(len(b))}
		return d, store.Push(ctx, d, bytes.NewReader(b))
	}
	layer, err := push(o.MediaType, o.Data)
	if err != nil {
		return err
	}
	config, err := push("application/vnd.enbu.config.v1+json", []byte("{}"))
	if err != nil {
		return err
	}
	m := ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: config, Layers: []ocispec.Descriptor{layer}}
	if s.SourceURL != "" {
		m.Annotations = map[string]string{"org.opencontainers.image.source": s.SourceURL}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	d, err := push(ocispec.MediaTypeImageManifest, b)
	if err != nil {
		return err
	}
	if err := store.Tag(ctx, d, key); err != nil {
		return err
	}
	current, err := s.Repository.Resolve(ctx, key)
	if err != nil && !errors.Is(err, errdef.ErrNotFound) {
		return remoteError(err)
	}
	if err == nil && Version(current.Digest) != expected || err != nil && expected != "" {
		return ErrConflict
	}
	// Distribution has no atomic conditional manifest PUT. This check is best effort.
	_, err = oras.Copy(ctx, store, key, s.Repository, key, oras.DefaultCopyOptions)
	return remoteError(err)
}

func (s *OCI) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	err := s.Repository.Tags(ctx, "", func(tags []string) error {
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

package oci

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/enbu-net/enbu/apperr"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
)

const emptyConfigJSON = "{}"

type PushOptions struct {
	SourceRepo     string
	ExpectedDigest string
}

func Push(ctx context.Context, ref string, mediaType string, data []byte, token string, opts *PushOptions) error {
	repo, err := newRepository(ref, token)
	if err != nil {
		return err
	}

	store := memory.New()

	layerDesc, err := pushBlob(ctx, store, mediaType, data)
	if err != nil {
		return fmt.Errorf("storing layer: %w", err)
	}

	configDesc, err := pushBlob(ctx, store, "application/vnd.enbu.config.v1+json", []byte(emptyConfigJSON))
	if err != nil {
		return fmt.Errorf("storing config: %w", err)
	}

	annotations := map[string]string{}
	if opts != nil && opts.SourceRepo != "" {
		annotations["org.opencontainers.image.source"] = opts.SourceRepo
	}

	manifest := ocispec.Manifest{
		Versioned:   specs.Versioned{SchemaVersion: 2},
		MediaType:   ocispec.MediaTypeImageManifest,
		Config:      configDesc,
		Layers:      []ocispec.Descriptor{layerDesc},
		Annotations: annotations,
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}

	manifestDesc, err := pushBlob(ctx, store, ocispec.MediaTypeImageManifest, manifestJSON)
	if err != nil {
		return fmt.Errorf("storing manifest: %w", err)
	}

	tag := repo.Reference.Reference
	if err := store.Tag(ctx, manifestDesc, tag); err != nil {
		return fmt.Errorf("tagging manifest: %w", err)
	}

	if opts != nil && opts.ExpectedDigest != "" {
		currentDigest, err := GetDigest(ctx, ref, token)
		if err != nil {
			return fmt.Errorf("getting current digest: %w", err)
		}
		if currentDigest != opts.ExpectedDigest {
			return apperr.New(apperr.CodeConflict, "remote reference changed", apperr.Params{
				"expected": opts.ExpectedDigest,
				"actual":   currentDigest,
			})
		}
	}

	_, err = oras.Copy(ctx, store, tag, repo, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("pushing to %s: %w", ref, err)
	}

	return nil
}

func pushBlob(ctx context.Context, store *memory.Store, mediaType string, data []byte) (ocispec.Descriptor, error) {
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digestOf(data),
		Size:      int64(len(data)),
	}

	if err := store.Push(ctx, desc, bytesReader(data)); err != nil {
		return ocispec.Descriptor{}, err
	}

	return desc, nil
}

// Package opaque treats one plaintext payload as uninterpreted bytes.
package opaque

import (
	"context"
	"errors"
	"io"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/content"
	"github.com/opencontainers/go-digest"
)

const PayloadName = "content"

var (
	ErrUnsupportedSchema = errors.New("unsupported Opaque schema")
	ErrInvalidOpaque     = errors.New("expected one Opaque content payload")
)

func Schema() artifact.TypeRef {
	return artifact.TypeRef{Group: "schemas.enbu.net", Version: "v1", Kind: "Opaque"}
}

// PayloadRef describes caller-owned plaintext without consuming or resolving it.
func PayloadRef(mediaType string, size uint64, hash digest.Digest) (artifact.PayloadRef, error) {
	ref := artifact.PayloadRef{Name: PayloadName, MediaType: mediaType, Size: size, Digest: hash}
	if err := ref.Validate(); err != nil {
		return artifact.PayloadRef{}, err
	}
	return ref, nil
}

// VerifyArtifact copies borrowed streams without interpreting their bytes or
// closing them. Written bytes remain unverified until this returns nil; callers
// must stage the destination before publishing it (see content.VerifyCopy).
func VerifyArtifact(ctx context.Context, a artifact.Artifact, dst io.Writer, src io.Reader) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.Schema != Schema() {
		return ErrUnsupportedSchema
	}
	if len(a.Payloads) != 1 || a.Payloads[0].Name != PayloadName {
		return ErrInvalidOpaque
	}
	return content.VerifyCopy(ctx, dst, src, a.Payloads[0])
}

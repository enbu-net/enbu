package artifact

import (
	"context"
	"fmt"
	"io"
	"mime"

	"github.com/opencontainers/go-digest"
)

const (
	MediaTypeEncryptedChunk        = "application/vnd.enbu.artifact.chunk.v1"
	MediaTypeEncryptedMaterial     = "application/vnd.enbu.artifact.material.v1+cbor"
	MediaTypeAccessGrant           = "application/vnd.enbu.artifact.grant.v1+cbor"
	MediaTypeEncryptedCommit       = "application/vnd.enbu.artifact.commit.v1+cbor"
	MediaTypeCommitAnnouncement    = "application/vnd.enbu.artifact.announcement.v1+cbor"
	MediaTypePluginPackage         = "application/vnd.enbu.plugin.v1"
	MediaTypeEncryptedAuditSegment = "application/vnd.enbu.audit.segment.v1+cbor"
)

// Descriptor identifies one immutable object. Size is the number of stored
// bytes, not the size of any plaintext represented by the object.
type Descriptor struct {
	MediaType string        `cbor:"mediaType" json:"mediaType"`
	Digest    digest.Digest `cbor:"digest" json:"digest"`
	Size      int64         `cbor:"size" json:"size"`
}

func (d Descriptor) Validate() error {
	if d.MediaType == "" {
		return fmt.Errorf("%w: descriptor has empty media type", ErrInvalidArtifact)
	}
	if _, _, err := mime.ParseMediaType(d.MediaType); err != nil {
		return fmt.Errorf("%w: descriptor media type: %v", ErrInvalidArtifact, err)
	}
	if err := validateDigest(d.Digest); err != nil {
		return fmt.Errorf("%w: descriptor digest: %v", ErrInvalidArtifact, err)
	}
	if d.Size < 0 {
		return fmt.Errorf("%w: descriptor has negative size", ErrInvalidArtifact)
	}
	return nil
}

// ObjectSink atomically ingests an immutable object while computing its
// descriptor. Implementations must not publish a partial object.
type ObjectSink interface {
	Ingest(context.Context, string, io.Reader) (Descriptor, error)
}

// ObjectSource opens an immutable object by digest. The returned descriptor
// describes the exact bytes read from the stream and is verified by callers.
type ObjectSource interface {
	Open(context.Context, digest.Digest) (io.ReadCloser, Descriptor, error)
}

// ExpectedObjectSource fetches through a complete trusted descriptor. Remote
// registries should implement it so untrusted manifest metadata can never
// poison a process-global digest-to-media-type cache. Callers still verify the
// returned stream through size, digest, and EOF.
type ExpectedObjectSource interface {
	OpenExpected(context.Context, Descriptor) (io.ReadCloser, error)
}

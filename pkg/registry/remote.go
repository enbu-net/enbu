package registry

import (
	"context"
	"io"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

// ObjectRemote is an immutable, streaming remote content store. Push MUST
// verify the supplied descriptor and be idempotent only for identical bytes
// and media type.
type ObjectRemote interface {
	Push(context.Context, artifact.Descriptor, io.Reader) error
	Open(context.Context, digest.Digest) (io.ReadCloser, artifact.Descriptor, error)
	Has(context.Context, digest.Digest) (bool, error)
}

// AnnouncementRef is the index result after an OCI-specific implementation
// has resolved its manifest and selected the announcement object.
type AnnouncementRef struct {
	Tag        string
	Descriptor artifact.Descriptor
}

// AnnouncementPage is one bounded, deterministic page. Next is an opaque
// cursor and is empty only on the final page. A non-final page MUST contain
// exactly the requested limit so callers can bound page and cursor work.
type AnnouncementPage struct {
	Refs []AnnouncementRef
	Next string
}

// AnnouncementIndex exposes only immutable commit announcements. The retained
// descriptors let OCI implementations keep the complete encrypted closure
// reachable from the tagged manifest; they do not participate in trust.
type AnnouncementIndex interface {
	PublishAnnouncement(context.Context, string, artifact.Descriptor, []artifact.Descriptor) error
	ListAnnouncements(context.Context, string, int, *VerificationBudget) (AnnouncementPage, error)
}

type Remote interface {
	ObjectRemote
	AnnouncementIndex
}

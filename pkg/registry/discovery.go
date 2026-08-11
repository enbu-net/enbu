package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/opencontainers/go-digest"
)

const (
	discoveryPageSize         = 256
	MaxDiscoveryAnnouncements = commitmodel.MaxDAGCommits
	maxDiscoveryCursorBytes   = 4 * 1024
	maxDiscoveryPages         = MaxDiscoveryAnnouncements/discoveryPageSize + 1
)

// VerifiedCommit is the authenticated Commit result required by discovery.
// Implementations must open and validate the Grant, authenticate the Grant
// issuer's announcement signature, consume all streams through EOF, verify the
// embedded author enrollment and signed canonical Commit, and enforce the
// cross-object bindings before returning this value.
type VerifiedCommit struct {
	CommitID          digest.Digest
	WorkspaceID       artifact.UUID
	CommitSignerKeyID digest.Digest
	EncryptedCommit   artifact.Descriptor
	Grant             artifact.Descriptor
	Value             commitmodel.VerifiedCommit
	openedGrant       artifact.OpenedGrant
}

// RewrapAccessGrant creates a new envelope for this already authenticated
// encrypted Commit. The material identity never leaves the verified value;
// callers can only ask for a newly signed Grant bound to the exact Commit and
// policy revision that were verified together.
func (commit VerifiedCommit) RewrapAccessGrant(
	ctx context.Context,
	issuer *artifact.DeviceIdentity,
	recipients []artifact.VerifiedDevice,
) (artifact.AccessGrant, error) {
	if commit.Value.Commit().Policy.Revision == "" || commit.openedGrant.Claims.Material != commit.EncryptedCommit.Digest {
		return artifact.AccessGrant{}, errors.New("registry: verified Commit has no rewrappable Grant capability")
	}
	return artifact.CreateAccessGrant(
		ctx,
		commit.EncryptedCommit.Digest,
		commit.Value.Commit().Policy.Revision,
		commit.openedGrant.Identity,
		issuer,
		recipients,
	)
}

type CommitVerifier interface {
	VerifyCommit(context.Context, CommitAnnouncement, *VerificationBudget) (VerifiedCommit, error)
}

// announcementRetentionRegistrar is implemented by remotes whose mutable
// visibility ref points to a second, bounded retention tree. Registration is
// deliberately sequenced after Commit authentication so unauthenticated tag
// listing cannot populate digest-global object lookup.
type announcementRetentionRegistrar interface {
	registerAnnouncementRetention(
		context.Context,
		string,
		artifact.Descriptor,
		CommitAnnouncement,
		*VerificationBudget,
	) error
}

type VerifiedAnnouncement struct {
	Tag          string
	Descriptor   artifact.Descriptor
	Announcement CommitAnnouncement
	Commit       VerifiedCommit
}

type Rejection struct {
	Tag  string
	Code RejectionCode
}

type InaccessibleAnnouncement struct {
	Tag      string
	CommitID digest.Digest
}

type Discovery struct {
	Announcements []VerifiedAnnouncement
	Rejections    []Rejection
	Inaccessible  []InaccessibleAnnouncement
}

// BuildDAG deduplicates verified envelope variants by logical Commit ID and
// constructs the complete authenticated DAG without decrypting them again.
func (d Discovery) BuildDAG(ctx context.Context) (*commitmodel.DAG, error) {
	byID := make(map[digest.Digest]commitmodel.VerifiedCommit, len(d.Announcements))
	for _, announcement := range d.Announcements {
		byID[announcement.Commit.CommitID] = announcement.Commit.Value
	}
	values := make([]commitmodel.VerifiedCommit, 0, len(byID))
	for _, value := range byID {
		values = append(values, value)
	}
	return commitmodel.BuildVerifiedDAG(ctx, values)
}

// Discover verifies every immutable commit announcement independently. A
// hostile entry becomes a stable rejection; list and transport failures abort
// the operation so a partial frontier cannot be mistaken for a complete one.
func Discover(
	ctx context.Context,
	workspaceID artifact.UUID,
	remote Remote,
	commits CommitVerifier,
) (Discovery, error) {
	if err := ctx.Err(); err != nil {
		return Discovery{}, err
	}
	if remote == nil || commits == nil {
		return Discovery{}, errors.New("registry: nil discovery dependency")
	}
	if err := workspaceID.Validate(); err != nil {
		return Discovery{}, fmt.Errorf("registry: invalid expected workspace ID: %w", err)
	}
	budget := newVerificationBudget()
	refs, err := listAnnouncementRefs(ctx, remote, budget)
	if err != nil {
		return Discovery{}, err
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Tag == refs[j].Tag {
			if refs[i].Descriptor.Digest == refs[j].Descriptor.Digest {
				return refs[i].Descriptor.MediaType < refs[j].Descriptor.MediaType
			}
			return refs[i].Descriptor.Digest < refs[j].Descriptor.Digest
		}
		return refs[i].Tag < refs[j].Tag
	})

	var result Discovery
	for first := 0; first < len(refs); {
		if err := ctx.Err(); err != nil {
			return Discovery{}, err
		}
		last := first + 1
		for last < len(refs) && refs[last].Tag == refs[first].Tag {
			last++
		}
		group := refs[first:last]
		first = last

		if !strings.HasPrefix(group[0].Tag, announcementTagPrefix) {
			continue
		}
		expectedDigest, err := ParseAnnouncementTag(group[0].Tag)
		if err != nil {
			result.reject(group[0].Tag, RejectionInvalidTag)
			continue
		}
		if ambiguousAnnouncementRefs(group) {
			result.reject(group[0].Tag, RejectionAmbiguousTag)
			continue
		}
		ref := group[0]
		if err := validateDescriptor(ref.Descriptor, artifact.MediaTypeCommitAnnouncement); err != nil {
			result.reject(ref.Tag, RejectionInvalidDescriptor)
			continue
		}
		if ref.Descriptor.Digest != expectedDigest {
			result.reject(ref.Tag, RejectionDigestMismatch)
			continue
		}
		if err := budget.ConsumeBytes(ref.Descriptor.Size); err != nil {
			return Discovery{}, err
		}
		encoded, err := readVerifiedRemoteObject(ctx, remote, ref.Descriptor, MaxAnnouncementBytes)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Discovery{}, ctxErr
			}
			if isRejectedObjectError(err) {
				result.reject(ref.Tag, RejectionInvalidDescriptor)
				continue
			}
			return Discovery{}, fmt.Errorf("read announcement %q: %w", ref.Tag, err)
		}
		announcement, err := DecodeCommitAnnouncement(encoded)
		if err != nil {
			result.reject(ref.Tag, RejectionInvalidAnnouncement)
			continue
		}
		if announcement.WorkspaceID != workspaceID {
			continue
		}
		verified, err := commits.VerifyCommit(ctx, announcement, budget)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Discovery{}, ctxErr
			}
			switch {
			case errors.Is(err, artifact.ErrGrantAccessDenied):
				result.Inaccessible = append(result.Inaccessible, InaccessibleAnnouncement{Tag: ref.Tag, CommitID: announcement.CommitID})
				continue
			case errors.Is(err, ErrInvalidAnnouncementSignature):
				result.reject(ref.Tag, RejectionInvalidSignature)
				continue
			case errors.Is(err, ErrInvalidCommitVerification), isRejectedObjectError(err):
				result.reject(ref.Tag, RejectionInvalidCommit)
				continue
			default:
				return Discovery{}, fmt.Errorf("verify announced Commit %q: %w", ref.Tag, err)
			}
		}
		if !commitMatchesAnnouncement(verified, announcement) {
			result.reject(ref.Tag, RejectionInvalidBinding)
			continue
		}
		if registrar, ok := remote.(announcementRetentionRegistrar); ok {
			if err := registrar.registerAnnouncementRetention(ctx, ref.Tag, ref.Descriptor, announcement, budget); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return Discovery{}, ctxErr
				}
				if isRejectedObjectError(err) {
					result.reject(ref.Tag, RejectionInvalidDescriptor)
					continue
				}
				return Discovery{}, fmt.Errorf("verify announced retention %q: %w", ref.Tag, err)
			}
		}
		result.Announcements = append(result.Announcements, VerifiedAnnouncement{
			Tag:          ref.Tag,
			Descriptor:   ref.Descriptor,
			Announcement: announcement,
			Commit:       verified,
		})
	}

	sort.Slice(result.Announcements, func(i, j int) bool {
		if result.Announcements[i].Commit.CommitID == result.Announcements[j].Commit.CommitID {
			return result.Announcements[i].Tag < result.Announcements[j].Tag
		}
		return result.Announcements[i].Commit.CommitID < result.Announcements[j].Commit.CommitID
	})
	sort.Slice(result.Rejections, func(i, j int) bool {
		if result.Rejections[i].Tag == result.Rejections[j].Tag {
			return result.Rejections[i].Code < result.Rejections[j].Code
		}
		return result.Rejections[i].Tag < result.Rejections[j].Tag
	})
	sort.Slice(result.Inaccessible, func(i, j int) bool {
		if result.Inaccessible[i].CommitID == result.Inaccessible[j].CommitID {
			return result.Inaccessible[i].Tag < result.Inaccessible[j].Tag
		}
		return result.Inaccessible[i].CommitID < result.Inaccessible[j].CommitID
	})
	return result, nil
}

func listAnnouncementRefs(ctx context.Context, index AnnouncementIndex, budget *VerificationBudget) ([]AnnouncementRef, error) {
	refs := make([]AnnouncementRef, 0, discoveryPageSize)
	seenCursors := map[string]struct{}{"": {}}
	cursor := ""
	for pageNumber := 0; pageNumber < maxDiscoveryPages; pageNumber++ {
		page, err := index.ListAnnouncements(ctx, cursor, discoveryPageSize, budget)
		if err != nil {
			return nil, err
		}
		if len(page.Refs) > discoveryPageSize || len(refs) > MaxDiscoveryAnnouncements-len(page.Refs) {
			return nil, errors.New("registry: announcement listing exceeds bounded protocol limits")
		}
		refs = append(refs, page.Refs...)
		if page.Next == "" {
			return refs, nil
		}
		if len(page.Refs) != discoveryPageSize {
			return nil, errors.New("registry: non-final announcement page is not full")
		}
		if len(page.Next) > maxDiscoveryCursorBytes {
			return nil, errors.New("registry: oversized announcement cursor")
		}
		if _, exists := seenCursors[page.Next]; exists {
			return nil, errors.New("registry: announcement cursor did not progress")
		}
		seenCursors[page.Next] = struct{}{}
		cursor = page.Next
	}
	return nil, errors.New("registry: announcement listing exceeds page limit")
}

func (d *Discovery) reject(tag string, code RejectionCode) {
	d.Rejections = append(d.Rejections, Rejection{Tag: tag, Code: code})
}

func ambiguousAnnouncementRefs(refs []AnnouncementRef) bool {
	for i := 1; i < len(refs); i++ {
		if refs[i].Descriptor != refs[0].Descriptor {
			return true
		}
	}
	return false
}

func readVerifiedRemoteObject(
	ctx context.Context,
	remote artifact.ObjectSource,
	expected artifact.Descriptor,
	maxBytes int64,
) (encoded []byte, returnedErr error) {
	if expected.Size < 0 || expected.Size > maxBytes {
		return nil, fmt.Errorf("%w: object exceeds read limit", ErrInvalidRemoteObject)
	}
	reader, descriptor, err := openExpectedObject(ctx, remote, expected)
	if err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("%w: remote returned nil reader", ErrInvalidRemoteObject)
	}
	defer func() {
		if closeErr := reader.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close remote object: %w", closeErr)
		}
	}()
	if descriptor != expected {
		return nil, fmt.Errorf("%w: descriptor mismatch", ErrInvalidRemoteObject)
	}
	var destination bytes.Buffer
	destination.Grow(int(expected.Size))
	observed := newObservedContextReader(ctx, reader, expected.Size)
	if _, err := destination.ReadFrom(observed); err != nil {
		return nil, observed.classifyReadError(err)
	}
	if err := observed.complete(expected); err != nil {
		return nil, err
	}
	return destination.Bytes(), nil
}

func isRejectedObjectError(err error) bool {
	return errors.Is(err, ErrInvalidRemoteObject) || errors.Is(err, ErrObjectNotFound)
}

func commitMatchesAnnouncement(commit VerifiedCommit, announcement CommitAnnouncement) bool {
	return commit.CommitID == announcement.CommitID &&
		commit.WorkspaceID == announcement.WorkspaceID &&
		commit.Value.Digest() == commit.CommitID &&
		commit.Value.Commit().WorkspaceID == commit.WorkspaceID &&
		commit.Value.SignerKeyID() == commit.CommitSignerKeyID &&
		commit.EncryptedCommit == announcement.EncryptedCommit &&
		commit.Grant == announcement.Grant
}

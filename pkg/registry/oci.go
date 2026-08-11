package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
)

const (
	// OCIAnnouncementArtifactType identifies the OCI image index used as the
	// visibility point for one commit announcement. The index points to one
	// constant-size bootstrap manifest and zero or more retention shards.
	OCIAnnouncementArtifactType = "application/vnd.enbu.artifact.announcement-index.v1"
	// OCIAnnouncementBootstrapArtifactType identifies the manifest containing
	// only the announcement and its exact Grant/Commit bootstrap descriptors.
	OCIAnnouncementBootstrapArtifactType = "application/vnd.enbu.artifact.announcement-bootstrap.v1"
	// OCIRetentionShardArtifactType identifies a bounded manifest retaining one
	// deterministic partition of the remaining encrypted object closure.
	OCIRetentionShardArtifactType = "application/vnd.enbu.artifact.retention-shard.v1"
	// OCIAnnouncementConfigMediaType identifies the fixed, empty configuration
	// blob of an announcement manifest.
	OCIAnnouncementConfigMediaType = "application/vnd.enbu.artifact.announcement-config.v1+json"

	MaxOCIAnnouncementManifestBytes        = 4 * 1024 * 1024
	MaxOCIRetentionShardLayers             = 10_000
	MaxOCIAnnouncementIndexManifests       = 1 + (MaxPublicationObjects-2+MaxOCIRetentionShardLayers-1)/MaxOCIRetentionShardLayers
	MaxOCIAnnouncementPageSize             = 1_000
	MaxOCIRawTagsPerPage                   = 10_000
	ociRawTagBudgetCost              int64 = 256

	ociAnnouncementCursorPrefix = "oci-tags-v1."
)

var (
	emptyOCIAnnouncementConfig = []byte("{}")
	errInvalidOCIManifest      = errors.New("registry: invalid OCI announcement manifest")
	errInvalidOCITagListing    = errors.New("registry: invalid OCI tag listing")
	errStopOCITagListing       = errors.New("registry: stop OCI tag listing")
)

// OCITarget is the ORAS target surface needed by OCIRemote. A real
// *remote.Repository implements it. Tests and local stores may provide tag
// enumeration around an oras.Target.
type OCITarget interface {
	oras.Target
	Tags(context.Context, string, func([]string) error) error
}

// OCIRemote adapts an ORAS repository or target to the streaming registry
// contracts. Object descriptors learned from verified pushes and the
// authenticated announcement/Grant/Commit bootstrap are retained in memory
// because OCI blob lookup by digest alone does not preserve the layer media
// type. Unauthenticated retained layers are never registered implicitly.
type OCIRemote struct {
	target OCITarget

	descriptorMu sync.RWMutex
	descriptors  map[digest.Digest]artifact.Descriptor
	// retainedDescriptors are learned only after an announcement and Commit
	// authenticate successfully. Unlike descriptors learned from Push or an
	// explicitly verified registration, they remain a set: cross-media claims
	// for identical bytes become ambiguous and fail closed instead of allowing
	// whichever announcement was listed first to poison digest-global lookup.
	retainedDescriptors map[digest.Digest]map[artifact.Descriptor]struct{}
	publishMu           sync.Mutex
}

var _ Remote = (*OCIRemote)(nil)
var _ artifact.ExpectedObjectSource = (*OCIRemote)(nil)

// NewOCIRemote constructs an OCI-backed registry remote.
func NewOCIRemote(target OCITarget) (*OCIRemote, error) {
	if target == nil || (reflect.ValueOf(target).Kind() == reflect.Pointer && reflect.ValueOf(target).IsNil()) {
		return nil, errors.New("registry: nil OCI target")
	}
	return &OCIRemote{
		target:              target,
		descriptors:         make(map[digest.Digest]artifact.Descriptor),
		retainedDescriptors: make(map[digest.Digest]map[artifact.Descriptor]struct{}),
	}, nil
}

// Push streams and verifies one immutable blob. An existing identical object
// is idempotent; a conflicting descriptor for the digest is rejected.
func (r *OCIRemote) Push(ctx context.Context, expected artifact.Descriptor, source io.Reader) error {
	if ctx == nil {
		return errors.New("registry: nil context")
	}
	if source == nil {
		return errors.New("registry: nil OCI push source")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := expected.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRemoteObject, err)
	}
	if existing, ok := r.knownDescriptor(expected.Digest); ok && existing != expected {
		return fmt.Errorf("%w: digest already has media type %q and size %d", ErrInvalidRemoteObject, existing.MediaType, existing.Size)
	}

	targetDescriptor := toOCIDescriptor(expected)
	exists, err := r.target.Exists(ctx, targetDescriptor)
	if err != nil {
		return normalizeOCIContextError(ctx, err)
	}
	if exists {
		if err := consumeExpectedObject(ctx, source, expected); err != nil {
			return err
		}
		if err := r.verifyTargetObject(ctx, expected); err != nil {
			return err
		}
		return r.rememberDescriptor(expected)
	}

	observed := newObservedContextReader(ctx, source, expected.Size)
	pushErr := r.target.Push(ctx, targetDescriptor, observed)
	if pushErr != nil && errors.Is(pushErr, errdef.ErrAlreadyExists) {
		if _, err := io.CopyBuffer(io.Discard, observed, make([]byte, registryCopyBufferSize)); err != nil {
			return normalizeOCIContextError(ctx, observed.classifyReadError(err))
		}
		pushErr = nil
	}
	if pushErr != nil {
		return normalizeOCIContextError(ctx, observed.classifyReadError(pushErr))
	}
	if err := observed.complete(expected); err != nil {
		return normalizeOCIContextError(ctx, observed.classifyReadError(err))
	}
	if err := r.verifyTargetObject(ctx, expected); err != nil {
		return err
	}
	return r.rememberDescriptor(expected)
}

// Open streams a known object by digest. Descriptors become known through
// Push or through a strictly validated announcement manifest.
func (r *OCIRemote) Open(ctx context.Context, objectDigest digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	if ctx == nil {
		return nil, artifact.Descriptor{}, errors.New("registry: nil context")
	}
	if err := validateDigest(objectDigest); err != nil {
		return nil, artifact.Descriptor{}, fmt.Errorf("%w: %v", ErrInvalidRemoteObject, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	descriptor, err := r.lookupDescriptor(objectDigest)
	if errors.Is(err, ErrObjectNotFound) {
		return nil, artifact.Descriptor{}, ErrObjectNotFound
	}
	if err != nil {
		return nil, artifact.Descriptor{}, err
	}
	reader, err := r.OpenExpected(ctx, descriptor)
	if err != nil {
		return nil, artifact.Descriptor{}, err
	}
	return reader, descriptor, nil
}

// OpenExpected streams the exact caller-supplied descriptor without consulting
// the digest-global descriptor cache. This is the safe path for descriptors
// learned from signed or otherwise authenticated graph objects.
func (r *OCIRemote) OpenExpected(ctx context.Context, descriptor artifact.Descriptor) (io.ReadCloser, error) {
	if ctx == nil {
		return nil, errors.New("registry: nil context")
	}
	if err := descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRemoteObject, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, err := r.target.Fetch(ctx, toOCIDescriptor(descriptor))
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil, ErrObjectNotFound
		}
		return nil, normalizeOCIContextError(ctx, err)
	}
	if reader == nil {
		return nil, fmt.Errorf("%w: OCI target returned nil reader", ErrInvalidRemoteObject)
	}
	return &verifiedOCIReadCloser{
		ctx:      ctx,
		closer:   reader,
		observed: newObservedContextReader(ctx, reader, descriptor.Size),
		expected: descriptor,
	}, nil
}

// Has checks a descriptor previously learned from a push or announcement
// manifest. An unknown digest is a safe false negative and will be resolved by
// the descriptor-bearing Push path.
func (r *OCIRemote) Has(ctx context.Context, objectDigest digest.Digest) (bool, error) {
	if ctx == nil {
		return false, errors.New("registry: nil context")
	}
	if err := validateDigest(objectDigest); err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidRemoteObject, err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	descriptor, err := r.lookupDescriptor(objectDigest)
	if errors.Is(err, ErrObjectNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	exists, err := r.target.Exists(ctx, toOCIDescriptor(descriptor))
	if err != nil {
		return false, normalizeOCIContextError(ctx, err)
	}
	return exists, nil
}

// RegisterVerifiedDescriptors registers descriptors obtained from an
// authenticated object, such as a signed Commit. Every remote object is
// streamed and descriptor-verified before the batch becomes visible to Open
// or Has. Callers MUST NOT pass descriptors taken only from an unauthenticated
// OCI manifest.
func (r *OCIRemote) RegisterVerifiedDescriptors(ctx context.Context, descriptors []artifact.Descriptor) error {
	if ctx == nil {
		return errors.New("registry: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	verified := append([]artifact.Descriptor(nil), descriptors...)
	for _, descriptor := range verified {
		if err := descriptor.Validate(); err != nil {
			return fmt.Errorf("%w: verified descriptor: %v", ErrInvalidRemoteObject, err)
		}
		if err := r.verifyTargetObject(ctx, descriptor); err != nil {
			return err
		}
	}
	return r.rememberDescriptors(verified)
}

// PublishAnnouncement creates a deterministic OCI image index retaining the
// encrypted closure through bounded shard manifests and applies the content-
// derived tag only after every referenced blob and metadata object is present.
func (r *OCIRemote) PublishAnnouncement(
	ctx context.Context,
	tag string,
	announcement artifact.Descriptor,
	retained []artifact.Descriptor,
) error {
	if ctx == nil {
		return errors.New("registry: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateAnnouncementDescriptor(announcement); err != nil {
		return err
	}
	wantTag, err := AnnouncementTag(announcement.Digest)
	if err != nil || tag != wantTag {
		return fmt.Errorf("%w: tag does not match announcement digest", ErrInvalidAnnouncement)
	}
	ordered, err := canonicalOCIRetained(retained, announcement)
	if err != nil {
		return err
	}

	announcementBytes, err := r.fetchArtifactBytes(ctx, announcement, MaxAnnouncementBytes)
	if err != nil {
		return fmt.Errorf("verify announcement blob before tagging: %w", err)
	}
	decodedAnnouncement, err := DecodeCommitAnnouncement(announcementBytes)
	if err != nil {
		return fmt.Errorf("%w: announcement blob is not canonical: %v", ErrInvalidAnnouncement, err)
	}
	if err := requireAnnouncementRetention(ordered, decodedAnnouncement); err != nil {
		return err
	}
	for _, descriptor := range ordered {
		if err := r.verifyTargetObject(ctx, descriptor); err != nil {
			return fmt.Errorf("verify retained object %s before metadata publication: %w", descriptor.Digest, err)
		}
	}
	configDescriptor := ociAnnouncementConfigDescriptor()
	if err := r.pushFixedOCIBytes(ctx, configDescriptor, emptyOCIAnnouncementConfig); err != nil {
		return fmt.Errorf("publish announcement config: %w", err)
	}
	bootstrapRetained, shardRetained, err := partitionOCIRetained(ordered, decodedAnnouncement)
	if err != nil {
		return err
	}
	_, bootstrapBytes, bootstrapDescriptor, err := buildOCIAnnouncementBootstrapManifest(announcement, bootstrapRetained)
	if err != nil {
		return err
	}
	if err := r.pushFixedOCIBytes(ctx, bootstrapDescriptor, bootstrapBytes); err != nil {
		return fmt.Errorf("publish announcement bootstrap: %w", err)
	}
	shardDescriptors := make([]ocispec.Descriptor, 0, retentionShardCount(len(shardRetained)))
	for first := 0; first < len(shardRetained); first += MaxOCIRetentionShardLayers {
		last := min(first+MaxOCIRetentionShardLayers, len(shardRetained))
		_, shardBytes, shardDescriptor, err := buildOCIRetentionShardManifest(shardRetained[first:last])
		if err != nil {
			return err
		}
		if err := r.pushFixedOCIBytes(ctx, shardDescriptor, shardBytes); err != nil {
			return fmt.Errorf("publish retention shard %d: %w", len(shardDescriptors), err)
		}
		shardDescriptors = append(shardDescriptors, shardDescriptor)
	}
	index, indexBytes, indexDescriptor, err := buildOCIAnnouncementIndex(bootstrapDescriptor, shardDescriptors)
	if err != nil {
		return err
	}
	if err := r.pushFixedOCIBytes(ctx, indexDescriptor, indexBytes); err != nil {
		return fmt.Errorf("publish announcement index: %w", err)
	}
	// The index is the only mutable visibility point. Re-read its complete
	// one-level closure after every child has been uploaded, validate the exact
	// descriptor set, and verify every retained object before allowing Tag.
	// This catches registries that accepted an upload but lost, truncated, or
	// substituted a bootstrap, shard, index, config, or retained object while
	// the publication was still in flight.
	if err := r.verifyOCIAnnouncementPublication(
		ctx,
		indexDescriptor,
		index,
		announcement,
		decodedAnnouncement,
		ordered,
	); err != nil {
		return fmt.Errorf("verify announcement publication before tagging: %w", err)
	}

	r.publishMu.Lock()
	defer r.publishMu.Unlock()
	resolved, err := r.target.Resolve(ctx, tag)
	if err == nil {
		if err := r.requireIdenticalAnnouncementIndex(ctx, resolved, indexDescriptor, index); err != nil {
			return err
		}
		return nil
	}
	if !errors.Is(err, errdef.ErrNotFound) {
		return normalizeOCIContextError(ctx, err)
	}
	if err := r.target.Tag(ctx, indexDescriptor, tag); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		// A concurrent honest publisher may have installed the same tag.
		resolved, resolveErr := r.target.Resolve(ctx, tag)
		if resolveErr != nil {
			return err
		}
		if identicalErr := r.requireIdenticalAnnouncementIndex(ctx, resolved, indexDescriptor, index); identicalErr != nil {
			return identicalErr
		}
		return nil
	}
	// Tag is the publication point of no return. Verification after it must not
	// inherit caller cancellation, otherwise a visible publication could be
	// reported as canceled. A bounded detached context still catches a registry
	// that substituted the tag at the visibility boundary.
	verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	resolved, err = r.target.Resolve(verifyCtx, tag)
	if err != nil {
		return normalizeOCIContextError(verifyCtx, err)
	}
	return r.requireIdenticalAnnouncementIndex(verifyCtx, resolved, indexDescriptor, index)
}

// ListAnnouncements enumerates one bounded page of commit-* tags. OCI Tags is
// required to progress in strict lexical order, which makes the opaque cursor
// deterministic without retaining an unbounded client-side tag set.
// Structurally hostile manifests become independent refs that Discover
// rejects; transport failures abort to avoid presenting an incomplete
// frontier.
func (r *OCIRemote) ListAnnouncements(
	ctx context.Context,
	cursor string,
	limit int,
	budget *VerificationBudget,
) (AnnouncementPage, error) {
	if ctx == nil {
		return AnnouncementPage{}, errors.New("registry: nil context")
	}
	if err := ctx.Err(); err != nil {
		return AnnouncementPage{}, err
	}
	if limit <= 0 || limit > MaxOCIAnnouncementPageSize {
		return AnnouncementPage{}, fmt.Errorf("%w: page limit must be between 1 and %d", errInvalidOCITagListing, MaxOCIAnnouncementPageSize)
	}
	if err := budget.ConsumeBytes(0); err != nil {
		return AnnouncementPage{}, err
	}
	last, err := decodeOCIAnnouncementCursor(cursor)
	if err != nil {
		return AnnouncementPage{}, err
	}
	tags, rawLast, more, err := r.listOCIAnnouncementTags(ctx, last, limit, budget)
	if err != nil {
		return AnnouncementPage{}, err
	}

	refs := make([]AnnouncementRef, 0, len(tags))
	for _, tag := range tags {
		if err := ctx.Err(); err != nil {
			return AnnouncementPage{}, err
		}
		ref, err := r.resolveOCIAnnouncementRef(ctx, tag, budget)
		if err != nil {
			return AnnouncementPage{}, err
		}
		refs = append(refs, ref)
	}

	page := AnnouncementPage{Refs: refs}
	if more {
		page.Next = encodeOCIAnnouncementCursor(rawLast)
		if page.Next == cursor {
			return AnnouncementPage{}, fmt.Errorf("%w: cursor did not progress", errInvalidOCITagListing)
		}
	}
	return page, nil
}

func (r *OCIRemote) listOCIAnnouncementTags(
	ctx context.Context,
	last string,
	limit int,
	budget *VerificationBudget,
) ([]string, string, bool, error) {
	tags := make([]string, 0, limit)
	previous := last
	resume := ""
	scanned := 0
	err := r.target.Tags(ctx, last, func(page []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, tag := range page {
			if scanned >= MaxOCIRawTagsPerPage {
				if len(tags) == limit {
					resume = previous
					return errStopOCITagListing
				}
				return fmt.Errorf("%w: OCI raw tag page exceeds %d entries", ErrDiscoveryBudgetExceeded, MaxOCIRawTagsPerPage)
			}
			if err := budget.ConsumeBytes(ociRawTagBudgetCost); err != nil {
				if len(tags) == limit {
					resume = previous
					return errStopOCITagListing
				}
				return err
			}
			scanned++
			if !isValidOCITag(tag) {
				return fmt.Errorf("%w: target returned malformed tag", errInvalidOCITagListing)
			}
			if tag <= previous {
				return fmt.Errorf("%w: tag %q does not progress after %q", errInvalidOCITagListing, tag, previous)
			}
			before := previous
			previous = tag
			if !strings.HasPrefix(tag, announcementTagPrefix) {
				continue
			}
			if len(tags) == limit {
				resume = before
				return errStopOCITagListing
			}
			tags = append(tags, tag)
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopOCITagListing) {
		return nil, "", false, normalizeOCIContextError(ctx, err)
	}
	if errors.Is(err, errStopOCITagListing) {
		if len(tags) != limit || resume == "" {
			return nil, "", false, fmt.Errorf("%w: invalid bounded tag-listing state", errInvalidOCITagListing)
		}
		return tags, resume, true, nil
	}
	return tags, previous, false, nil
}

func (r *OCIRemote) resolveOCIAnnouncementRef(
	ctx context.Context,
	tag string,
	budget *VerificationBudget,
) (AnnouncementRef, error) {
	ref := AnnouncementRef{Tag: tag}
	if _, err := ParseAnnouncementTag(tag); err != nil {
		return ref, nil
	}
	manifestDescriptor, err := r.target.Resolve(ctx, tag)
	if err != nil {
		return AnnouncementRef{}, normalizeOCIContextError(ctx, err)
	}
	ref.Descriptor = fromOCIDescriptor(manifestDescriptor)
	_, bootstrapDescriptor, _, err := r.loadOCIAnnouncementIndex(ctx, manifestDescriptor, budget)
	if err != nil {
		if errors.Is(err, errInvalidOCIManifest) {
			return ref, nil
		}
		return AnnouncementRef{}, err
	}
	bootstrap, announcementDescriptor, _, err := r.loadOCIAnnouncementBootstrap(ctx, bootstrapDescriptor, budget)
	if err != nil {
		if errors.Is(err, errInvalidOCIManifest) {
			return ref, nil
		}
		return AnnouncementRef{}, err
	}
	_, err = r.validateOCIAnnouncementBootstrap(ctx, bootstrap, announcementDescriptor, budget)
	if err != nil {
		if errors.Is(err, errInvalidOCIManifest) {
			return ref, nil
		}
		return AnnouncementRef{}, err
	}
	ref.Descriptor = announcementDescriptor
	return ref, nil
}

// registerAnnouncementRetention traverses and registers one OCI retention
// tree only after Discover has authenticated the announcement and its Commit.
// ListAnnouncements intentionally does not call this method: listing remains
// bootstrap-only, and unauthenticated public metadata cannot affect digest-
// global Open/Has behavior.
func (r *OCIRemote) registerAnnouncementRetention(
	ctx context.Context,
	tag string,
	expectedDescriptor artifact.Descriptor,
	expectedAnnouncement CommitAnnouncement,
	budget *VerificationBudget,
) error {
	expectedDigest, err := ParseAnnouncementTag(tag)
	if err != nil || expectedDescriptor.Digest != expectedDigest {
		return fmt.Errorf("%w: retention tag binding", ErrInvalidRemoteObject)
	}
	if err := budget.ConsumeBytes(int64(len(emptyOCIAnnouncementConfig))); err != nil {
		return err
	}
	config, err := r.fetchOCIBytes(
		ctx,
		ociAnnouncementConfigDescriptor(),
		int64(len(emptyOCIAnnouncementConfig)),
	)
	if err != nil {
		return classifyOCIRetentionError("config", err)
	}
	if !bytes.Equal(config, emptyOCIAnnouncementConfig) {
		return fmt.Errorf("%w: retention config bytes differ", ErrInvalidRemoteObject)
	}

	rootDescriptor, err := r.target.Resolve(ctx, tag)
	if err != nil {
		return classifyOCIRetentionError("resolve root", normalizeOCIContextError(ctx, err))
	}
	_, bootstrapDescriptor, shardDescriptors, err := r.loadOCIAnnouncementIndex(ctx, rootDescriptor, budget)
	if err != nil {
		return classifyOCIRetentionError("root index", err)
	}
	bootstrap, announcementDescriptor, bootstrapRetained, err := r.loadOCIAnnouncementBootstrap(
		ctx,
		bootstrapDescriptor,
		budget,
	)
	if err != nil {
		return classifyOCIRetentionError("bootstrap", err)
	}
	if announcementDescriptor != expectedDescriptor {
		return fmt.Errorf("%w: retention bootstrap announcement binding", ErrInvalidRemoteObject)
	}
	announcement, err := r.validateOCIAnnouncementBootstrap(ctx, bootstrap, announcementDescriptor, budget)
	if err != nil {
		return classifyOCIRetentionError("bootstrap announcement", err)
	}
	if !reflect.DeepEqual(announcement, expectedAnnouncement) {
		return fmt.Errorf("%w: retention announcement changed after verification", ErrInvalidRemoteObject)
	}

	retained := append([]artifact.Descriptor(nil), bootstrapRetained...)
	for index, shardDescriptor := range shardDescriptors {
		_, shardRetained, _, err := r.loadOCIRetentionShard(ctx, shardDescriptor, budget)
		if err != nil {
			return classifyOCIRetentionError(fmt.Sprintf("shard %d", index), err)
		}
		if len(retained) > MaxPublicationObjects-len(shardRetained) {
			return fmt.Errorf("%w: retention closure exceeds %d descriptors", ErrInvalidRemoteObject, MaxPublicationObjects)
		}
		retained = append(retained, shardRetained...)
	}
	canonical, err := canonicalOCIRetained(retained, announcementDescriptor)
	if err != nil {
		return fmt.Errorf("%w: retention closure: %v", ErrInvalidRemoteObject, err)
	}
	if err := requireAnnouncementRetention(canonical, expectedAnnouncement); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRemoteObject, err)
	}
	return r.rememberRetainedDescriptors(canonical)
}

func classifyOCIRetentionError(name string, err error) error {
	if isInvalidOCIObjectError(err) {
		return fmt.Errorf("%w: invalid OCI retention %s: %v", ErrInvalidRemoteObject, name, err)
	}
	return fmt.Errorf("OCI retention %s: %w", name, err)
}

func (r *OCIRemote) requireIdenticalAnnouncementIndex(
	ctx context.Context,
	resolved, expectedDescriptor ocispec.Descriptor,
	expected ocispec.Index,
) error {
	actual, bootstrapDescriptor, shardDescriptors, err := r.loadOCIAnnouncementIndex(ctx, resolved, nil)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, errInvalidOCIManifest) {
			return fmt.Errorf("%w: existing tag is not a valid announcement index", ErrAnnouncementConflict)
		}
		return err
	}
	bootstrap, announcementDescriptor, _, err := r.loadOCIAnnouncementBootstrap(ctx, bootstrapDescriptor, nil)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, errInvalidOCIManifest) {
			return fmt.Errorf("%w: existing tag has an invalid announcement bootstrap", ErrAnnouncementConflict)
		}
		return err
	}
	if _, err := r.validateOCIAnnouncementBootstrap(ctx, bootstrap, announcementDescriptor, nil); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, errInvalidOCIManifest) {
			return fmt.Errorf("%w: existing tag has an invalid announcement closure", ErrAnnouncementConflict)
		}
		return err
	}
	for index, descriptor := range shardDescriptors {
		if _, _, _, err := r.loadOCIRetentionShard(ctx, descriptor, nil); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, errInvalidOCIManifest) {
				return fmt.Errorf("%w: existing tag has invalid retention shard %d", ErrAnnouncementConflict, index)
			}
			return err
		}
	}
	if !bareOCIDescriptorsEqual(resolved, expectedDescriptor) || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("%w: existing tag names a different index", ErrAnnouncementConflict)
	}
	return nil
}

// verifyOCIAnnouncementPublication performs the last pre-visibility check for
// a publication. It deliberately walks only the bounded root metadata tree;
// tag enumeration remains bootstrap-only, while authenticated retention
// traversal accounts child metadata against the shared discovery budget.
func (r *OCIRemote) verifyOCIAnnouncementPublication(
	ctx context.Context,
	expectedIndexDescriptor ocispec.Descriptor,
	expectedIndex ocispec.Index,
	expectedAnnouncementDescriptor artifact.Descriptor,
	expectedAnnouncement CommitAnnouncement,
	expectedRetained []artifact.Descriptor,
) error {
	configDescriptor := ociAnnouncementConfigDescriptor()
	config, err := r.fetchOCIBytes(ctx, configDescriptor, int64(len(emptyOCIAnnouncementConfig)))
	if err != nil {
		return fmt.Errorf("announcement config: %w", err)
	}
	if !bytes.Equal(config, emptyOCIAnnouncementConfig) {
		return fmt.Errorf("%w: announcement config bytes differ", ErrInvalidRemoteObject)
	}

	actualIndex, bootstrapDescriptor, shardDescriptors, err := r.loadOCIAnnouncementIndex(
		ctx,
		expectedIndexDescriptor,
		nil,
	)
	if err != nil {
		return fmt.Errorf("announcement index: %w", err)
	}
	if !reflect.DeepEqual(actualIndex, expectedIndex) {
		return fmt.Errorf("%w: announcement index differs from publication plan", ErrInvalidRemoteObject)
	}

	bootstrap, announcementDescriptor, bootstrapRetained, err := r.loadOCIAnnouncementBootstrap(
		ctx,
		bootstrapDescriptor,
		nil,
	)
	if err != nil {
		return fmt.Errorf("announcement bootstrap: %w", err)
	}
	if announcementDescriptor != expectedAnnouncementDescriptor {
		return fmt.Errorf("%w: bootstrap announcement descriptor differs", ErrInvalidRemoteObject)
	}
	announcement, err := r.validateOCIAnnouncementBootstrap(ctx, bootstrap, announcementDescriptor, nil)
	if err != nil {
		return fmt.Errorf("announcement bootstrap closure: %w", err)
	}
	if !reflect.DeepEqual(announcement, expectedAnnouncement) {
		return fmt.Errorf("%w: bootstrap announcement differs", ErrInvalidRemoteObject)
	}

	retained := append([]artifact.Descriptor(nil), bootstrapRetained...)
	for index, descriptor := range shardDescriptors {
		_, shardRetained, _, err := r.loadOCIRetentionShard(ctx, descriptor, nil)
		if err != nil {
			return fmt.Errorf("retention shard %d: %w", index, err)
		}
		retained = append(retained, shardRetained...)
		if len(retained) > MaxPublicationObjects {
			return fmt.Errorf("%w: retained descriptor count exceeds %d", ErrInvalidRemoteObject, MaxPublicationObjects)
		}
	}
	canonical, err := canonicalOCIRetained(retained, announcementDescriptor)
	if err != nil {
		return fmt.Errorf("retained descriptor closure: %w", err)
	}
	if !reflect.DeepEqual(canonical, expectedRetained) {
		return fmt.Errorf("%w: retained descriptor closure differs from publication plan", ErrInvalidRemoteObject)
	}

	for _, descriptor := range canonical {
		if err := r.verifyTargetObject(ctx, descriptor); err != nil {
			return fmt.Errorf("retained object %s: %w", descriptor.Digest, err)
		}
	}
	return nil
}

func (r *OCIRemote) loadOCIAnnouncementIndex(
	ctx context.Context,
	descriptor ocispec.Descriptor,
	budget *VerificationBudget,
) (ocispec.Index, ocispec.Descriptor, []ocispec.Descriptor, error) {
	if err := validateBareOCIDescriptor(descriptor); err != nil ||
		descriptor.MediaType != ocispec.MediaTypeImageIndex ||
		descriptor.Size <= 0 || descriptor.Size > MaxOCIAnnouncementManifestBytes {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: invalid index descriptor", errInvalidOCIManifest)
	}
	if budget != nil {
		if err := budget.ConsumeBytes(descriptor.Size); err != nil {
			return ocispec.Index{}, ocispec.Descriptor{}, nil, err
		}
	}
	encoded, err := r.fetchOCIBytes(ctx, descriptor, MaxOCIAnnouncementManifestBytes)
	if err != nil {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, err
	}
	index, bootstrap, shards, err := decodeAndValidateOCIAnnouncementIndex(encoded)
	if err != nil {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, err
	}
	return index, bootstrap, shards, nil
}

func (r *OCIRemote) loadOCIAnnouncementBootstrap(
	ctx context.Context,
	descriptor ocispec.Descriptor,
	budget *VerificationBudget,
) (ocispec.Manifest, artifact.Descriptor, []artifact.Descriptor, error) {
	if err := validateOCIChildManifestDescriptor(descriptor); err != nil {
		return ocispec.Manifest{}, artifact.Descriptor{}, nil, fmt.Errorf("%w: invalid bootstrap descriptor", errInvalidOCIManifest)
	}
	if budget != nil {
		if err := budget.ConsumeBytes(descriptor.Size); err != nil {
			return ocispec.Manifest{}, artifact.Descriptor{}, nil, err
		}
	}
	encoded, err := r.fetchOCIBytes(ctx, descriptor, MaxOCIAnnouncementManifestBytes)
	if err != nil {
		return ocispec.Manifest{}, artifact.Descriptor{}, nil, err
	}
	manifest, announcement, retained, err := decodeAndValidateOCIAnnouncementBootstrapManifest(encoded)
	if err != nil {
		return ocispec.Manifest{}, artifact.Descriptor{}, nil, err
	}
	return manifest, announcement, retained, nil
}

func (r *OCIRemote) loadOCIRetentionShard(
	ctx context.Context,
	descriptor ocispec.Descriptor,
	budget *VerificationBudget,
) (ocispec.Manifest, []artifact.Descriptor, []byte, error) {
	if err := validateOCIChildManifestDescriptor(descriptor); err != nil {
		return ocispec.Manifest{}, nil, nil, fmt.Errorf("%w: invalid retention shard descriptor", errInvalidOCIManifest)
	}
	if budget != nil {
		if err := budget.ConsumeBytes(descriptor.Size); err != nil {
			return ocispec.Manifest{}, nil, nil, err
		}
	}
	encoded, err := r.fetchOCIBytes(ctx, descriptor, MaxOCIAnnouncementManifestBytes)
	if err != nil {
		return ocispec.Manifest{}, nil, nil, err
	}
	manifest, retained, err := decodeAndValidateOCIRetentionShardManifest(encoded)
	if err != nil {
		return ocispec.Manifest{}, nil, nil, err
	}
	return manifest, retained, encoded, nil
}

func (r *OCIRemote) validateOCIAnnouncementBootstrap(
	ctx context.Context,
	manifest ocispec.Manifest,
	announcementDescriptor artifact.Descriptor,
	budget *VerificationBudget,
) (CommitAnnouncement, error) {
	if budget != nil {
		if err := budget.ConsumeBytes(announcementDescriptor.Size); err != nil {
			return CommitAnnouncement{}, err
		}
	}
	encoded, err := r.fetchArtifactBytes(ctx, announcementDescriptor, MaxAnnouncementBytes)
	if err != nil {
		if isInvalidOCIObjectError(err) {
			return CommitAnnouncement{}, fmt.Errorf("%w: announcement blob: %v", errInvalidOCIManifest, err)
		}
		return CommitAnnouncement{}, err
	}
	announcement, err := DecodeCommitAnnouncement(encoded)
	if err != nil {
		return CommitAnnouncement{}, fmt.Errorf("%w: announcement blob: %v", errInvalidOCIManifest, err)
	}
	retained := make([]artifact.Descriptor, len(manifest.Layers)-1)
	for index, layer := range manifest.Layers[1:] {
		retained[index] = fromOCIDescriptor(layer)
	}
	if err := requireAnnouncementRetention(retained, announcement); err != nil {
		return CommitAnnouncement{}, fmt.Errorf("%w: %v", errInvalidOCIManifest, err)
	}
	return announcement, nil
}

func (r *OCIRemote) fetchOCIBytes(ctx context.Context, descriptor ocispec.Descriptor, maximum int64) (data []byte, returnedErr error) {
	if descriptor.Size < 0 || descriptor.Size > maximum {
		return nil, fmt.Errorf("%w: object exceeds size limit", errInvalidOCIManifest)
	}
	reader, err := r.target.Fetch(ctx, descriptor)
	if err != nil {
		return nil, normalizeOCIContextError(ctx, err)
	}
	if reader == nil {
		return nil, fmt.Errorf("%w: OCI target returned nil reader", errInvalidOCIManifest)
	}
	defer func() {
		if closeErr := reader.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close OCI object: %w", closeErr)
		}
	}()
	var destination bytes.Buffer
	destination.Grow(int(descriptor.Size))
	observed := newObservedContextReader(ctx, reader, descriptor.Size)
	if _, err := destination.ReadFrom(observed); err != nil {
		classified := observed.classifyReadError(err)
		if errors.Is(classified, ErrInvalidRemoteObject) {
			return nil, fmt.Errorf("%w: manifest bytes: %v", errInvalidOCIManifest, classified)
		}
		return nil, normalizeOCIContextError(ctx, classified)
	}
	expected := fromOCIDescriptor(descriptor)
	if err := observed.complete(expected); err != nil {
		classified := observed.classifyReadError(err)
		if errors.Is(classified, ErrInvalidRemoteObject) {
			return nil, fmt.Errorf("%w: manifest bytes: %v", errInvalidOCIManifest, classified)
		}
		return nil, normalizeOCIContextError(ctx, classified)
	}
	return destination.Bytes(), nil
}

func (r *OCIRemote) fetchArtifactBytes(ctx context.Context, descriptor artifact.Descriptor, maximum int64) (data []byte, returnedErr error) {
	if descriptor.Size < 0 || descriptor.Size > maximum {
		return nil, fmt.Errorf("%w: object exceeds size limit", ErrInvalidRemoteObject)
	}
	reader, err := r.target.Fetch(ctx, toOCIDescriptor(descriptor))
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil, ErrObjectNotFound
		}
		return nil, normalizeOCIContextError(ctx, err)
	}
	if reader == nil {
		return nil, fmt.Errorf("%w: OCI target returned nil reader", ErrInvalidRemoteObject)
	}
	defer func() {
		if closeErr := reader.Close(); returnedErr == nil && closeErr != nil {
			returnedErr = fmt.Errorf("close OCI object: %w", closeErr)
		}
	}()
	var destination bytes.Buffer
	destination.Grow(int(descriptor.Size))
	observed := newObservedContextReader(ctx, reader, descriptor.Size)
	if _, err := destination.ReadFrom(observed); err != nil {
		return nil, normalizeOCIContextError(ctx, observed.classifyReadError(err))
	}
	if err := observed.complete(descriptor); err != nil {
		return nil, normalizeOCIContextError(ctx, observed.classifyReadError(err))
	}
	return destination.Bytes(), nil
}

func (r *OCIRemote) pushFixedOCIBytes(ctx context.Context, descriptor ocispec.Descriptor, data []byte) error {
	exists, err := r.target.Exists(ctx, descriptor)
	if err != nil {
		return normalizeOCIContextError(ctx, err)
	}
	if !exists {
		if err := r.target.Push(ctx, descriptor, bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			return normalizeOCIContextError(ctx, err)
		}
	}
	actual, err := r.fetchOCIBytes(ctx, descriptor, int64(len(data)))
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, data) {
		return fmt.Errorf("%w: fixed OCI object differs", ErrInvalidRemoteObject)
	}
	return nil
}

func (r *OCIRemote) verifyTargetObject(ctx context.Context, descriptor artifact.Descriptor) error {
	reader, err := r.target.Fetch(ctx, toOCIDescriptor(descriptor))
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return ErrObjectNotFound
		}
		return normalizeOCIContextError(ctx, err)
	}
	if reader == nil {
		return fmt.Errorf("%w: OCI target returned nil reader", ErrInvalidRemoteObject)
	}
	observed := newObservedContextReader(ctx, reader, descriptor.Size)
	_, copyErr := io.CopyBuffer(io.Discard, observed, make([]byte, registryCopyBufferSize))
	closeErr := reader.Close()
	if copyErr != nil {
		return normalizeOCIContextError(ctx, observed.classifyReadError(copyErr))
	}
	if closeErr != nil {
		return normalizeOCIContextError(ctx, closeErr)
	}
	if err := observed.complete(descriptor); err != nil {
		return normalizeOCIContextError(ctx, observed.classifyReadError(err))
	}
	return nil
}

func (r *OCIRemote) rememberDescriptor(descriptor artifact.Descriptor) error {
	return r.rememberDescriptors([]artifact.Descriptor{descriptor})
}

func (r *OCIRemote) rememberDescriptors(descriptors []artifact.Descriptor) error {
	for _, descriptor := range descriptors {
		if err := descriptor.Validate(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidRemoteObject, err)
		}
	}
	r.descriptorMu.Lock()
	defer r.descriptorMu.Unlock()
	batch := make(map[digest.Digest]artifact.Descriptor, len(descriptors))
	for _, descriptor := range descriptors {
		if existing, ok := batch[descriptor.Digest]; ok && existing != descriptor {
			return fmt.Errorf("%w: conflicting descriptor for %s", ErrInvalidRemoteObject, descriptor.Digest)
		}
		batch[descriptor.Digest] = descriptor
		if existing, ok := r.descriptors[descriptor.Digest]; ok && existing != descriptor {
			return fmt.Errorf("%w: conflicting descriptor for %s", ErrInvalidRemoteObject, descriptor.Digest)
		}
	}
	for objectDigest, descriptor := range batch {
		r.descriptors[objectDigest] = descriptor
	}
	return nil
}

func (r *OCIRemote) knownDescriptor(objectDigest digest.Digest) (artifact.Descriptor, bool) {
	r.descriptorMu.RLock()
	defer r.descriptorMu.RUnlock()
	descriptor, ok := r.descriptors[objectDigest]
	return descriptor, ok
}

func (r *OCIRemote) lookupDescriptor(objectDigest digest.Digest) (artifact.Descriptor, error) {
	r.descriptorMu.RLock()
	defer r.descriptorMu.RUnlock()
	if descriptor, ok := r.descriptors[objectDigest]; ok {
		return descriptor, nil
	}
	candidates := r.retainedDescriptors[objectDigest]
	if len(candidates) == 0 {
		return artifact.Descriptor{}, ErrObjectNotFound
	}
	if len(candidates) != 1 {
		return artifact.Descriptor{}, fmt.Errorf("%w: ambiguous retained descriptor for %s", ErrInvalidRemoteObject, objectDigest)
	}
	for descriptor := range candidates {
		return descriptor, nil
	}
	return artifact.Descriptor{}, fmt.Errorf("%w: empty retained descriptor set for %s", ErrInvalidRemoteObject, objectDigest)
}

func (r *OCIRemote) rememberRetainedDescriptors(descriptors []artifact.Descriptor) error {
	if len(descriptors) > MaxPublicationObjects {
		return fmt.Errorf("%w: retained descriptor count exceeds %d", ErrInvalidRemoteObject, MaxPublicationObjects)
	}
	batch := make(map[digest.Digest]artifact.Descriptor, len(descriptors))
	for _, descriptor := range descriptors {
		if err := validateRetainedArtifactDescriptor(descriptor); err != nil {
			return err
		}
		if existing, ok := batch[descriptor.Digest]; ok && existing != descriptor {
			return fmt.Errorf("%w: conflicting retained descriptor for %s", ErrInvalidRemoteObject, descriptor.Digest)
		}
		batch[descriptor.Digest] = descriptor
	}
	r.descriptorMu.Lock()
	defer r.descriptorMu.Unlock()
	for objectDigest, descriptor := range batch {
		candidates := r.retainedDescriptors[objectDigest]
		if candidates == nil {
			candidates = make(map[artifact.Descriptor]struct{}, 1)
			r.retainedDescriptors[objectDigest] = candidates
		}
		candidates[descriptor] = struct{}{}
	}
	return nil
}

func buildOCIAnnouncementBootstrapManifest(
	announcement artifact.Descriptor,
	retained []artifact.Descriptor,
) (ocispec.Manifest, []byte, ocispec.Descriptor, error) {
	if err := validateAnnouncementDescriptor(announcement); err != nil {
		return ocispec.Manifest{}, nil, ocispec.Descriptor{}, err
	}
	if len(retained) != 2 {
		return ocispec.Manifest{}, nil, ocispec.Descriptor{}, fmt.Errorf("%w: bootstrap must retain exactly Grant and Commit", ErrInvalidAnnouncement)
	}
	canonical, err := canonicalOCIRetained(retained, announcement)
	if err != nil {
		return ocispec.Manifest{}, nil, ocispec.Descriptor{}, err
	}
	mediaTypes := map[string]int{}
	for _, descriptor := range canonical {
		mediaTypes[descriptor.MediaType]++
	}
	if mediaTypes[artifact.MediaTypeAccessGrant] != 1 || mediaTypes[artifact.MediaTypeEncryptedCommit] != 1 {
		return ocispec.Manifest{}, nil, ocispec.Descriptor{}, fmt.Errorf("%w: bootstrap must contain one Grant and one Commit", ErrInvalidAnnouncement)
	}
	layers := []ocispec.Descriptor{toOCIDescriptor(announcement)}
	for _, descriptor := range canonical {
		layers = append(layers, toOCIDescriptor(descriptor))
	}
	manifest := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: OCIAnnouncementBootstrapArtifactType,
		Config:       ociAnnouncementConfigDescriptor(),
		Layers:       layers,
	}
	encoded, descriptor, err := encodeOCIManifest(manifest, "announcement bootstrap")
	return manifest, encoded, descriptor, err
}

func buildOCIRetentionShardManifest(
	retained []artifact.Descriptor,
) (ocispec.Manifest, []byte, ocispec.Descriptor, error) {
	if len(retained) == 0 || len(retained) > MaxOCIRetentionShardLayers {
		return ocispec.Manifest{}, nil, ocispec.Descriptor{}, fmt.Errorf("%w: retention shard must contain 1-%d layers", ErrInvalidRemoteObject, MaxOCIRetentionShardLayers)
	}
	canonical, err := canonicalRetainedDescriptors(retained, nil)
	if err != nil {
		return ocispec.Manifest{}, nil, ocispec.Descriptor{}, err
	}
	layers := make([]ocispec.Descriptor, len(canonical))
	for index, descriptor := range canonical {
		layers[index] = toOCIDescriptor(descriptor)
	}
	manifest := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: OCIRetentionShardArtifactType,
		Config:       ociAnnouncementConfigDescriptor(),
		Layers:       layers,
	}
	encoded, descriptor, err := encodeOCIManifest(manifest, "retention shard")
	return manifest, encoded, descriptor, err
}

func buildOCIAnnouncementIndex(
	bootstrap ocispec.Descriptor,
	shards []ocispec.Descriptor,
) (ocispec.Index, []byte, ocispec.Descriptor, error) {
	if err := validateOCIChildManifestDescriptor(bootstrap); err != nil {
		return ocispec.Index{}, nil, ocispec.Descriptor{}, fmt.Errorf("%w: bootstrap descriptor: %v", ErrInvalidRemoteObject, err)
	}
	if len(shards)+1 > MaxOCIAnnouncementIndexManifests {
		return ocispec.Index{}, nil, ocispec.Descriptor{}, fmt.Errorf("%w: announcement index exceeds %d manifests", ErrInvalidRemoteObject, MaxOCIAnnouncementIndexManifests)
	}
	canonical := append([]ocispec.Descriptor(nil), shards...)
	seen := map[digest.Digest]ocispec.Descriptor{bootstrap.Digest: bootstrap}
	for index, descriptor := range canonical {
		if err := validateOCIChildManifestDescriptor(descriptor); err != nil {
			return ocispec.Index{}, nil, ocispec.Descriptor{}, fmt.Errorf("%w: shard descriptor %d: %v", ErrInvalidRemoteObject, index, err)
		}
		if existing, ok := seen[descriptor.Digest]; ok {
			return ocispec.Index{}, nil, ocispec.Descriptor{}, fmt.Errorf("%w: duplicate or conflicting child manifest %s (%s)", ErrInvalidRemoteObject, descriptor.Digest, existing.MediaType)
		}
		seen[descriptor.Digest] = descriptor
	}
	sort.Slice(canonical, func(i, j int) bool { return compareOCIDescriptor(canonical[i], canonical[j]) < 0 })
	manifests := make([]ocispec.Descriptor, 0, len(canonical)+1)
	manifests = append(manifests, bootstrap)
	manifests = append(manifests, canonical...)
	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: OCIAnnouncementArtifactType,
		Manifests:    manifests,
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		return ocispec.Index{}, nil, ocispec.Descriptor{}, fmt.Errorf("encode OCI announcement index: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxOCIAnnouncementManifestBytes {
		return ocispec.Index{}, nil, ocispec.Descriptor{}, fmt.Errorf("registry: OCI announcement index exceeds %d bytes", MaxOCIAnnouncementManifestBytes)
	}
	descriptor := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromBytes(encoded), Size: int64(len(encoded))}
	return index, encoded, descriptor, nil
}

func encodeOCIManifest(manifest ocispec.Manifest, name string) ([]byte, ocispec.Descriptor, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("encode OCI %s manifest: %w", name, err)
	}
	if len(encoded) == 0 || len(encoded) > MaxOCIAnnouncementManifestBytes {
		return nil, ocispec.Descriptor{}, fmt.Errorf("registry: OCI %s manifest exceeds %d bytes", name, MaxOCIAnnouncementManifestBytes)
	}
	descriptor := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(encoded), Size: int64(len(encoded))}
	return encoded, descriptor, nil
}

func decodeAndValidateOCIAnnouncementIndex(encoded []byte) (ocispec.Index, ocispec.Descriptor, []ocispec.Descriptor, error) {
	if len(encoded) == 0 || len(encoded) > MaxOCIAnnouncementManifestBytes {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: index encoded size", errInvalidOCIManifest)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var index ocispec.Index
	if err := decoder.Decode(&index); err != nil {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: decode index JSON: %v", errInvalidOCIManifest, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: trailing index JSON", errInvalidOCIManifest)
	}
	canonical, err := json.Marshal(index)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: non-canonical index JSON", errInvalidOCIManifest)
	}
	if index.SchemaVersion != 2 || index.MediaType != ocispec.MediaTypeImageIndex ||
		index.ArtifactType != OCIAnnouncementArtifactType || index.Subject != nil || index.Annotations != nil {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: index envelope fields", errInvalidOCIManifest)
	}
	if len(index.Manifests) == 0 || len(index.Manifests) > MaxOCIAnnouncementIndexManifests {
		return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: index manifest count", errInvalidOCIManifest)
	}
	seen := make(map[digest.Digest]ocispec.Descriptor, len(index.Manifests))
	for position, descriptor := range index.Manifests {
		if err := validateOCIChildManifestDescriptor(descriptor); err != nil {
			return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: index manifest %d: %v", errInvalidOCIManifest, position, err)
		}
		if existing, ok := seen[descriptor.Digest]; ok {
			return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: duplicate or conflicting index manifest %s (%s)", errInvalidOCIManifest, descriptor.Digest, existing.MediaType)
		}
		seen[descriptor.Digest] = descriptor
		if position >= 2 && compareOCIDescriptor(index.Manifests[position-1], descriptor) >= 0 {
			return ocispec.Index{}, ocispec.Descriptor{}, nil, fmt.Errorf("%w: shard manifests are not canonical", errInvalidOCIManifest)
		}
	}
	return index, index.Manifests[0], append([]ocispec.Descriptor(nil), index.Manifests[1:]...), nil
}

func decodeAndValidateOCIAnnouncementBootstrapManifest(encoded []byte) (ocispec.Manifest, artifact.Descriptor, []artifact.Descriptor, error) {
	manifest, err := decodeCanonicalOCIManifest(encoded, OCIAnnouncementBootstrapArtifactType)
	if err != nil {
		return ocispec.Manifest{}, artifact.Descriptor{}, nil, err
	}
	if len(manifest.Layers) != 3 {
		return ocispec.Manifest{}, artifact.Descriptor{}, nil, fmt.Errorf("%w: bootstrap layer count", errInvalidOCIManifest)
	}
	announcement := fromOCIDescriptor(manifest.Layers[0])
	if err := validateBareOCIDescriptor(manifest.Layers[0]); err != nil {
		return ocispec.Manifest{}, artifact.Descriptor{}, nil, fmt.Errorf("%w: bootstrap announcement descriptor: %v", errInvalidOCIManifest, err)
	}
	if err := validateAnnouncementDescriptor(announcement); err != nil {
		return ocispec.Manifest{}, artifact.Descriptor{}, nil, fmt.Errorf("%w: bootstrap announcement layer: %v", errInvalidOCIManifest, err)
	}
	retained := make([]artifact.Descriptor, 2)
	mediaTypes := map[string]int{}
	seen := map[digest.Digest]ocispec.Descriptor{manifest.Layers[0].Digest: manifest.Layers[0]}
	for position, layer := range manifest.Layers[1:] {
		if err := validateRetainedOCIDescriptor(layer); err != nil {
			return ocispec.Manifest{}, artifact.Descriptor{}, nil, fmt.Errorf("%w: bootstrap layer %d: %v", errInvalidOCIManifest, position+1, err)
		}
		if existing, ok := seen[layer.Digest]; ok {
			return ocispec.Manifest{}, artifact.Descriptor{}, nil, fmt.Errorf("%w: duplicate bootstrap layer %s (%s)", errInvalidOCIManifest, layer.Digest, existing.MediaType)
		}
		seen[layer.Digest] = layer
		mediaTypes[layer.MediaType]++
		retained[position] = fromOCIDescriptor(layer)
	}
	if mediaTypes[artifact.MediaTypeAccessGrant] != 1 || mediaTypes[artifact.MediaTypeEncryptedCommit] != 1 ||
		compareOCIDescriptor(manifest.Layers[1], manifest.Layers[2]) >= 0 {
		return ocispec.Manifest{}, artifact.Descriptor{}, nil, fmt.Errorf("%w: non-canonical Grant/Commit bootstrap", errInvalidOCIManifest)
	}
	return manifest, announcement, retained, nil
}

func decodeAndValidateOCIRetentionShardManifest(encoded []byte) (ocispec.Manifest, []artifact.Descriptor, error) {
	manifest, err := decodeCanonicalOCIManifest(encoded, OCIRetentionShardArtifactType)
	if err != nil {
		return ocispec.Manifest{}, nil, err
	}
	if len(manifest.Layers) == 0 || len(manifest.Layers) > MaxOCIRetentionShardLayers {
		return ocispec.Manifest{}, nil, fmt.Errorf("%w: retention shard layer count", errInvalidOCIManifest)
	}
	retained := make([]artifact.Descriptor, len(manifest.Layers))
	seen := make(map[digest.Digest]ocispec.Descriptor, len(manifest.Layers))
	for position, layer := range manifest.Layers {
		if err := validateRetainedOCIDescriptor(layer); err != nil {
			return ocispec.Manifest{}, nil, fmt.Errorf("%w: retention shard layer %d: %v", errInvalidOCIManifest, position, err)
		}
		if existing, ok := seen[layer.Digest]; ok {
			return ocispec.Manifest{}, nil, fmt.Errorf("%w: duplicate retention layer %s (%s)", errInvalidOCIManifest, layer.Digest, existing.MediaType)
		}
		seen[layer.Digest] = layer
		if position > 0 && compareOCIDescriptor(manifest.Layers[position-1], layer) >= 0 {
			return ocispec.Manifest{}, nil, fmt.Errorf("%w: retention layers are not canonical", errInvalidOCIManifest)
		}
		retained[position] = fromOCIDescriptor(layer)
	}
	return manifest, retained, nil
}

func decodeCanonicalOCIManifest(encoded []byte, artifactType string) (ocispec.Manifest, error) {
	if len(encoded) == 0 || len(encoded) > MaxOCIAnnouncementManifestBytes {
		return ocispec.Manifest{}, fmt.Errorf("%w: manifest encoded size", errInvalidOCIManifest)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest ocispec.Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return ocispec.Manifest{}, fmt.Errorf("%w: decode manifest JSON: %v", errInvalidOCIManifest, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ocispec.Manifest{}, fmt.Errorf("%w: trailing manifest JSON", errInvalidOCIManifest)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return ocispec.Manifest{}, fmt.Errorf("%w: non-canonical manifest JSON", errInvalidOCIManifest)
	}
	if manifest.SchemaVersion != 2 || manifest.MediaType != ocispec.MediaTypeImageManifest ||
		manifest.ArtifactType != artifactType || manifest.Subject != nil || manifest.Annotations != nil {
		return ocispec.Manifest{}, fmt.Errorf("%w: manifest envelope fields", errInvalidOCIManifest)
	}
	if !bareOCIDescriptorsEqual(manifest.Config, ociAnnouncementConfigDescriptor()) {
		return ocispec.Manifest{}, fmt.Errorf("%w: manifest config descriptor", errInvalidOCIManifest)
	}
	return manifest, nil
}

func canonicalOCIRetained(retained []artifact.Descriptor, announcement artifact.Descriptor) ([]artifact.Descriptor, error) {
	if len(retained) > MaxPublicationObjects {
		return nil, fmt.Errorf("registry: retained descriptor count exceeds %d", MaxPublicationObjects)
	}
	return canonicalRetainedDescriptors(retained, &announcement)
}

func canonicalRetainedDescriptors(retained []artifact.Descriptor, forbidden *artifact.Descriptor) ([]artifact.Descriptor, error) {
	ordered := append([]artifact.Descriptor(nil), retained...)
	seen := make(map[digest.Digest]artifact.Descriptor, len(ordered)+1)
	if forbidden != nil {
		if err := validateAnnouncementDescriptor(*forbidden); err != nil {
			return nil, err
		}
		seen[forbidden.Digest] = *forbidden
	}
	for _, descriptor := range ordered {
		if err := validateRetainedArtifactDescriptor(descriptor); err != nil {
			return nil, err
		}
		if existing, ok := seen[descriptor.Digest]; ok {
			return nil, fmt.Errorf("%w: duplicate or conflicting descriptor for %s (%s)", ErrInvalidRemoteObject, descriptor.Digest, existing.MediaType)
		}
		seen[descriptor.Digest] = descriptor
	}
	sort.Slice(ordered, func(i, j int) bool { return compareArtifactDescriptor(ordered[i], ordered[j]) < 0 })
	return ordered, nil
}

func partitionOCIRetained(
	ordered []artifact.Descriptor,
	announcement CommitAnnouncement,
) ([]artifact.Descriptor, []artifact.Descriptor, error) {
	if err := requireAnnouncementRetention(ordered, announcement); err != nil {
		return nil, nil, err
	}
	bootstrap := make([]artifact.Descriptor, 0, 2)
	shards := make([]artifact.Descriptor, 0, len(ordered)-2)
	for _, descriptor := range ordered {
		if descriptor == announcement.Grant || descriptor == announcement.EncryptedCommit {
			bootstrap = append(bootstrap, descriptor)
			continue
		}
		shards = append(shards, descriptor)
	}
	if len(bootstrap) != 2 {
		return nil, nil, fmt.Errorf("%w: ambiguous Grant/Commit bootstrap", ErrInvalidAnnouncement)
	}
	sort.Slice(bootstrap, func(i, j int) bool { return compareArtifactDescriptor(bootstrap[i], bootstrap[j]) < 0 })
	return bootstrap, shards, nil
}

func retentionShardCount(retained int) int {
	if retained <= 0 {
		return 0
	}
	return (retained + MaxOCIRetentionShardLayers - 1) / MaxOCIRetentionShardLayers
}

func requireAnnouncementRetention(retained []artifact.Descriptor, announcement CommitAnnouncement) error {
	required := []artifact.Descriptor{announcement.Grant, announcement.EncryptedCommit}
	for _, expected := range required {
		found := false
		for _, candidate := range retained {
			if candidate == expected {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: announcement object %s is not retained exactly", ErrInvalidAnnouncement, expected.Digest)
		}
	}
	return nil
}

func encodeOCIAnnouncementCursor(last string) string {
	return ociAnnouncementCursorPrefix + base64.RawURLEncoding.EncodeToString([]byte(last))
}

func decodeOCIAnnouncementCursor(cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	if !strings.HasPrefix(cursor, ociAnnouncementCursorPrefix) {
		return "", fmt.Errorf("%w: malformed cursor prefix", errInvalidOCITagListing)
	}
	encoded := strings.TrimPrefix(cursor, ociAnnouncementCursorPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || encodeOCIAnnouncementCursor(string(decoded)) != cursor {
		return "", fmt.Errorf("%w: malformed cursor encoding", errInvalidOCITagListing)
	}
	last := string(decoded)
	if !isValidOCITag(last) {
		return "", fmt.Errorf("%w: malformed cursor tag", errInvalidOCITagListing)
	}
	return last, nil
}

func isValidOCITag(tag string) bool {
	if len(tag) == 0 || len(tag) > 128 || !isOCITagInitial(tag[0]) {
		return false
	}
	for index := 1; index < len(tag); index++ {
		character := tag[index]
		if !isOCITagInitial(character) && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func isOCITagInitial(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		character == '_'
}

func isInvalidOCIObjectError(err error) bool {
	return errors.Is(err, errInvalidOCIManifest) ||
		errors.Is(err, ErrInvalidRemoteObject) ||
		errors.Is(err, ErrObjectNotFound) ||
		errors.Is(err, errdef.ErrNotFound)
}

func validateAnnouncementDescriptor(descriptor artifact.Descriptor) error {
	if err := validateDescriptor(descriptor, artifact.MediaTypeCommitAnnouncement); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAnnouncement, err)
	}
	if descriptor.Size <= 0 || descriptor.Size > MaxAnnouncementBytes {
		return fmt.Errorf("%w: announcement exceeds size limit", ErrInvalidAnnouncement)
	}
	return nil
}

func validateOCIChildManifestDescriptor(descriptor ocispec.Descriptor) error {
	if err := validateBareOCIDescriptor(descriptor); err != nil {
		return err
	}
	if descriptor.MediaType != ocispec.MediaTypeImageManifest || descriptor.Size <= 0 ||
		descriptor.Size > MaxOCIAnnouncementManifestBytes {
		return errors.New("descriptor is not a bounded OCI image manifest")
	}
	return nil
}

func validateRetainedOCIDescriptor(descriptor ocispec.Descriptor) error {
	if err := validateBareOCIDescriptor(descriptor); err != nil {
		return err
	}
	return validateRetainedMediaType(descriptor.MediaType)
}

func validateRetainedArtifactDescriptor(descriptor artifact.Descriptor) error {
	if err := descriptor.Validate(); err != nil {
		return fmt.Errorf("%w: retained descriptor: %v", ErrInvalidRemoteObject, err)
	}
	if err := validateRetainedMediaType(descriptor.MediaType); err != nil {
		return fmt.Errorf("%w: retained descriptor: %v", ErrInvalidRemoteObject, err)
	}
	return nil
}

func validateRetainedMediaType(mediaType string) error {
	switch mediaType {
	case artifact.MediaTypeEncryptedChunk,
		artifact.MediaTypeEncryptedMaterial,
		artifact.MediaTypeAccessGrant,
		artifact.MediaTypePluginPackage,
		artifact.MediaTypeEncryptedCommit:
		return nil
	default:
		return fmt.Errorf("unsupported retained media type %q", mediaType)
	}
}

func validateBareOCIDescriptor(descriptor ocispec.Descriptor) error {
	if descriptor.URLs != nil || descriptor.Annotations != nil || descriptor.Data != nil ||
		descriptor.Platform != nil || descriptor.ArtifactType != "" {
		return errors.New("descriptor contains forbidden metadata")
	}
	converted := fromOCIDescriptor(descriptor)
	if err := converted.Validate(); err != nil {
		return err
	}
	return nil
}

func ociAnnouncementConfigDescriptor() ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: OCIAnnouncementConfigMediaType,
		Digest:    digest.FromBytes(emptyOCIAnnouncementConfig),
		Size:      int64(len(emptyOCIAnnouncementConfig)),
	}
}

func toOCIDescriptor(descriptor artifact.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: descriptor.MediaType, Digest: descriptor.Digest, Size: descriptor.Size}
}

func fromOCIDescriptor(descriptor ocispec.Descriptor) artifact.Descriptor {
	return artifact.Descriptor{MediaType: descriptor.MediaType, Digest: descriptor.Digest, Size: descriptor.Size}
}

func bareOCIDescriptorsEqual(left, right ocispec.Descriptor) bool {
	return left.MediaType == right.MediaType && left.Digest == right.Digest && left.Size == right.Size &&
		left.URLs == nil && right.URLs == nil && left.Annotations == nil && right.Annotations == nil &&
		left.Data == nil && right.Data == nil && left.Platform == nil && right.Platform == nil &&
		left.ArtifactType == "" && right.ArtifactType == ""
}

func compareOCIDescriptor(left, right ocispec.Descriptor) int {
	if comparison := strings.Compare(left.Digest.String(), right.Digest.String()); comparison != 0 {
		return comparison
	}
	if comparison := strings.Compare(left.MediaType, right.MediaType); comparison != 0 {
		return comparison
	}
	if left.Size < right.Size {
		return -1
	}
	if left.Size > right.Size {
		return 1
	}
	return 0
}

func compareArtifactDescriptor(left, right artifact.Descriptor) int {
	return compareOCIDescriptor(toOCIDescriptor(left), toOCIDescriptor(right))
}

func consumeExpectedObject(ctx context.Context, source io.Reader, expected artifact.Descriptor) error {
	observed := newObservedContextReader(ctx, source, expected.Size)
	if _, err := io.CopyBuffer(io.Discard, observed, make([]byte, registryCopyBufferSize)); err != nil {
		return normalizeOCIContextError(ctx, observed.classifyReadError(err))
	}
	if err := observed.complete(expected); err != nil {
		return normalizeOCIContextError(ctx, observed.classifyReadError(err))
	}
	return nil
}

func normalizeOCIContextError(ctx context.Context, err error) error {
	if ctx != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	}
	return err
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

type verifiedOCIReadCloser struct {
	ctx      context.Context
	closer   io.ReadCloser
	observed *observedContextReader
	expected artifact.Descriptor
}

func (r *verifiedOCIReadCloser) Read(destination []byte) (int, error) {
	n, err := r.observed.Read(destination)
	if err == nil {
		return n, nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return n, err
	}
	if errors.Is(err, io.EOF) {
		if completeErr := r.observed.complete(r.expected); completeErr != nil {
			return n, r.observed.classifyReadError(completeErr)
		}
		return n, io.EOF
	}
	return n, r.observed.classifyReadError(err)
}

func (r *verifiedOCIReadCloser) Close() error {
	return r.closer.Close()
}

package registry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/opencontainers/go-digest"
)

func TestCommitAnnouncementRoundTripSignatureAndPrivacy(t *testing.T) {
	t.Parallel()

	fixture := newRegistryFixture(t)
	encoded, err := EncodeCommitAnnouncement(fixture.announcement)
	if err != nil {
		t.Fatalf("EncodeCommitAnnouncement: %v", err)
	}
	decoded, err := DecodeCommitAnnouncement(encoded)
	if err != nil {
		t.Fatalf("DecodeCommitAnnouncement: %v", err)
	}
	if err := VerifyCommitAnnouncement(context.Background(), decoded, fixture.signer.SigningPublicKey()); err != nil {
		t.Fatalf("VerifyCommitAnnouncement: %v", err)
	}
	for name, secret := range map[string]string{
		"subject":          fixture.enrollment.Subject(),
		"device ID":        string(fixture.signer.DeviceID()),
		"device recipient": fixture.signer.RecipientString(),
		"enrollment":       "signed-device-enrollment",
	} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Errorf("public announcement exposes %s", name)
		}
	}
	if bytes.Contains(encoded, fixture.signer.SigningPublicKey()) {
		t.Fatal("public announcement exposes the publisher signing key")
	}

	tampered := decoded
	tampered.CommitID = digest.FromString("substituted")
	if err := VerifyCommitAnnouncement(context.Background(), tampered, fixture.signer.SigningPublicKey()); !errors.Is(err, ErrInvalidAnnouncementSignature) {
		t.Fatalf("VerifyCommitAnnouncement(tampered) = %v, want signature error", err)
	}

	descriptor := descriptorFor(artifact.MediaTypeCommitAnnouncement, encoded)
	tag, err := AnnouncementTag(descriptor.Digest)
	if err != nil {
		t.Fatalf("AnnouncementTag: %v", err)
	}
	if parsed, err := ParseAnnouncementTag(tag); err != nil || parsed != descriptor.Digest {
		t.Fatalf("ParseAnnouncementTag(%q) = %s, %v", tag, parsed, err)
	}
	if _, err := ParseAnnouncementTag("commit-" + strings.ToUpper(descriptor.Digest.Encoded())); err == nil {
		t.Fatal("ParseAnnouncementTag accepted uppercase digest")
	}
}

func TestPublishOrdersObjectsAndUsesAnnouncementAsVisibilityPoint(t *testing.T) {
	t.Parallel()

	fixture := newRegistryFixture(t)
	remote := newMemoryRemote()
	closure := PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}}
	descriptor, err := Publish(context.Background(), remote, fixture.local, closure, fixture.announcement)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if descriptor.MediaType != artifact.MediaTypeCommitAnnouncement {
		t.Fatalf("announcement media type = %q", descriptor.MediaType)
	}
	page, err := remote.ListAnnouncements(context.Background(), "", discoveryPageSize, newVerificationBudget())
	if err != nil || len(page.Refs) != 1 {
		t.Fatalf("ListAnnouncements = %#v, %v", page, err)
	}
	wantTag, _ := AnnouncementTag(descriptor.Digest)
	if page.Refs[0].Tag != wantTag || page.Refs[0].Descriptor != descriptor {
		t.Fatalf("announcement ref = %#v, want %s/%#v", page.Refs[0], wantTag, descriptor)
	}

	remote.mu.Lock()
	events := append([]string(nil), remote.events...)
	remote.mu.Unlock()
	commitPush := eventIndex(events, "push:"+fixture.commit.Digest.String())
	announcementPush := eventIndex(events, "push:"+descriptor.Digest.String())
	tagPublish := eventIndex(events, "tag:"+wantTag)
	if commitPush < 0 || announcementPush <= commitPush || tagPublish <= announcementPush {
		t.Fatalf("publication order = %v", events)
	}
	for _, dependency := range []artifact.Descriptor{fixture.dependency, fixture.grant} {
		if index := eventIndex(events, "push:"+dependency.Digest.String()); index < 0 || index >= commitPush {
			t.Fatalf("dependency %s was not pushed before Commit: %v", dependency.Digest, events)
		}
	}

	if _, err := Publish(context.Background(), remote, fixture.local, closure, fixture.announcement); err != nil {
		t.Fatalf("idempotent Publish: %v", err)
	}
}

func TestPublishFailureNeverCreatesAnnouncementTag(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		fail func(*memoryRemote, registryFixture, artifact.Descriptor)
	}{
		{name: "dependency", fail: func(remote *memoryRemote, fixture registryFixture, _ artifact.Descriptor) {
			remote.failPush[fixture.dependency.Digest] = errors.New("dependency upload failed")
		}},
		{name: "commit", fail: func(remote *memoryRemote, fixture registryFixture, _ artifact.Descriptor) {
			remote.failPush[fixture.commit.Digest] = errors.New("commit upload failed")
		}},
		{name: "announcement", fail: func(remote *memoryRemote, _ registryFixture, announcement artifact.Descriptor) {
			remote.failPush[announcement.Digest] = errors.New("announcement upload failed")
		}},
		{name: "visibility point", fail: func(remote *memoryRemote, _ registryFixture, _ artifact.Descriptor) {
			remote.failTag = errors.New("tag failed")
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newRegistryFixture(t)
			remote := newMemoryRemote()
			encoded, err := EncodeCommitAnnouncement(fixture.announcement)
			if err != nil {
				t.Fatalf("EncodeCommitAnnouncement: %v", err)
			}
			announcementDescriptor := descriptorFor(artifact.MediaTypeCommitAnnouncement, encoded)
			test.fail(remote, fixture, announcementDescriptor)
			closure := PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}}
			if _, err := Publish(context.Background(), remote, fixture.local, closure, fixture.announcement); err == nil {
				t.Fatal("Publish succeeded despite injected failure")
			}
			page, err := remote.ListAnnouncements(context.Background(), "", discoveryPageSize, newVerificationBudget())
			if err != nil || len(page.Refs) != 0 {
				t.Fatalf("failed publication became visible: %#v, %v", page, err)
			}
		})
	}
}

func TestDiscoverIsDeterministicAndIgnoresMutableHints(t *testing.T) {
	t.Parallel()

	fixture := newRegistryFixture(t)
	remote := newMemoryRemote()
	closure := PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}}
	announcementDescriptor, err := Publish(context.Background(), remote, fixture.local, closure, fixture.announcement)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	tag, _ := AnnouncementTag(announcementDescriptor.Digest)
	remote.extraRefs = []AnnouncementRef{
		{Tag: "latest", Descriptor: announcementDescriptor},
		{Tag: "head", Descriptor: announcementDescriptor},
		{Tag: tag, Descriptor: announcementDescriptor},
	}

	result, err := Discover(context.Background(), fixture.announcement.WorkspaceID, remote, fixture.commits)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(result.Announcements) != 1 || len(result.Rejections) != 0 {
		t.Fatalf("Discovery = %#v", result)
	}
	if result.Announcements[0].Commit.CommitID != fixture.announcement.CommitID {
		t.Fatal("discovered wrong Commit")
	}
}

func TestDiscoverFiltersOtherWorkspacesBeforeCommitVerification(t *testing.T) {
	t.Parallel()

	fixture := newRegistryFixture(t)
	other := fixture.announcement
	other.WorkspaceID = mustUUID(t, "99999999-9999-4999-8999-999999999999")
	encoded, err := EncodeCommitAnnouncement(other)
	if err != nil {
		t.Fatalf("EncodeCommitAnnouncement: %v", err)
	}
	remote := newMemoryRemote()
	descriptor := remote.put(artifact.MediaTypeCommitAnnouncement, encoded)
	tag, _ := AnnouncementTag(descriptor.Digest)
	remote.extraRefs = []AnnouncementRef{{Tag: tag, Descriptor: descriptor}}
	called := false
	verifier := commitVerifierFunc(func(context.Context, CommitAnnouncement, *VerificationBudget) (VerifiedCommit, error) {
		called = true
		return VerifiedCommit{}, errors.New("must not verify another workspace")
	})

	result, err := Discover(context.Background(), fixture.announcement.WorkspaceID, remote, verifier)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if called || len(result.Announcements) != 0 || len(result.Rejections) != 0 || len(result.Inaccessible) != 0 {
		t.Fatalf("other workspace was not ignored before verification: called=%v result=%#v", called, result)
	}
}

func TestDiscoveryRejectsInvalidPagination(t *testing.T) {
	t.Parallel()

	validRef := AnnouncementRef{
		Tag: "commit-" + digest.FromString("page").Encoded(),
		Descriptor: artifact.Descriptor{
			MediaType: artifact.MediaTypeCommitAnnouncement,
			Digest:    digest.FromString("page"),
			Size:      1,
		},
	}
	fullPage := make([]AnnouncementRef, discoveryPageSize)
	for index := range fullPage {
		fullPage[index] = validRef
	}

	for _, test := range []struct {
		name string
		list func(string) AnnouncementPage
	}{
		{
			name: "short non-final page",
			list: func(string) AnnouncementPage {
				return AnnouncementPage{Refs: []AnnouncementRef{validRef}, Next: "next"}
			},
		},
		{
			name: "non-progressing cursor",
			list: func(cursor string) AnnouncementPage {
				if cursor == "" {
					return AnnouncementPage{Refs: fullPage, Next: "same"}
				}
				return AnnouncementPage{Refs: fullPage, Next: "same"}
			},
		},
		{
			name: "oversized cursor",
			list: func(string) AnnouncementPage {
				return AnnouncementPage{Refs: fullPage, Next: strings.Repeat("x", maxDiscoveryCursorBytes+1)}
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			index := announcementIndexFunc(func(_ context.Context, cursor string, _ int, _ *VerificationBudget) (AnnouncementPage, error) {
				return test.list(cursor), nil
			})
			if _, err := listAnnouncementRefs(context.Background(), index, newVerificationBudget()); err == nil {
				t.Fatal("invalid pagination was accepted")
			}
		})
	}
}

func TestDiscoveryBudgetExhaustionAbortsTheWholeResult(t *testing.T) {
	t.Parallel()

	fixture := newRegistryFixture(t)
	remote := newMemoryRemote()
	closure := PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}}
	if _, err := Publish(context.Background(), remote, fixture.local, closure, fixture.announcement); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	verifier := commitVerifierFunc(func(_ context.Context, _ CommitAnnouncement, budget *VerificationBudget) (VerifiedCommit, error) {
		return VerifiedCommit{}, budget.ConsumeBytes(MaxDiscoveryBytes)
	})
	result, err := Discover(context.Background(), fixture.announcement.WorkspaceID, remote, verifier)
	if !errors.Is(err, ErrDiscoveryBudgetExceeded) {
		t.Fatalf("Discover budget error = %v, want ErrDiscoveryBudgetExceeded", err)
	}
	if len(result.Announcements) != 0 || len(result.Rejections) != 0 || len(result.Inaccessible) != 0 {
		t.Fatalf("budget exhaustion returned a partial result: %#v", result)
	}
}

func TestDiscoverRejectsHostileEntriesIndependently(t *testing.T) {
	t.Parallel()

	fixture := newRegistryFixture(t)
	validRemote := newMemoryRemote()
	closure := PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}}
	validDescriptor, err := Publish(context.Background(), validRemote, fixture.local, closure, fixture.announcement)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	validTag, _ := AnnouncementTag(validDescriptor.Digest)

	t.Run("malformed tag", func(t *testing.T) {
		remote := validRemote.cloneObjects()
		remote.extraRefs = []AnnouncementRef{{Tag: "commit-NOT-A-DIGEST", Descriptor: validDescriptor}}
		result := mustDiscover(t, fixture.announcement.WorkspaceID, remote, fixture.commits)
		assertSingleRejection(t, result, RejectionInvalidTag)
	})

	t.Run("tag digest mismatch", func(t *testing.T) {
		remote := validRemote.cloneObjects()
		wrongTag, _ := AnnouncementTag(digest.FromString("other-announcement"))
		remote.extraRefs = []AnnouncementRef{{Tag: wrongTag, Descriptor: validDescriptor}}
		result := mustDiscover(t, fixture.announcement.WorkspaceID, remote, fixture.commits)
		assertSingleRejection(t, result, RejectionDigestMismatch)
	})

	t.Run("ambiguous duplicate tag", func(t *testing.T) {
		remote := validRemote.cloneObjects()
		other := descriptorFor(artifact.MediaTypeCommitAnnouncement, []byte("other"))
		remote.extraRefs = []AnnouncementRef{{Tag: validTag, Descriptor: validDescriptor}, {Tag: validTag, Descriptor: other}}
		result := mustDiscover(t, fixture.announcement.WorkspaceID, remote, fixture.commits)
		assertSingleRejection(t, result, RejectionAmbiguousTag)
	})

	t.Run("invalid announcement", func(t *testing.T) {
		remote := validRemote.cloneObjects()
		invalid := remote.put(artifact.MediaTypeCommitAnnouncement, []byte{0xff})
		tag, _ := AnnouncementTag(invalid.Digest)
		remote.extraRefs = []AnnouncementRef{{Tag: tag, Descriptor: invalid}}
		result := mustDiscover(t, fixture.announcement.WorkspaceID, remote, fixture.commits)
		assertSingleRejection(t, result, RejectionInvalidAnnouncement)
	})

	t.Run("invalid signature", func(t *testing.T) {
		remote := validRemote.cloneObjects()
		tampered := fixture.announcement
		tampered.Signature = append([]byte(nil), tampered.Signature...)
		tampered.Signature[0] ^= 0x80
		encoded, err := EncodeCommitAnnouncement(tampered)
		if err != nil {
			t.Fatalf("EncodeCommitAnnouncement: %v", err)
		}
		descriptor := remote.put(artifact.MediaTypeCommitAnnouncement, encoded)
		tag, _ := AnnouncementTag(descriptor.Digest)
		remote.extraRefs = []AnnouncementRef{{Tag: tag, Descriptor: descriptor}}
		result := mustDiscover(t, fixture.announcement.WorkspaceID, remote, fixture.commits)
		assertSingleRejection(t, result, RejectionInvalidSignature)
	})

	t.Run("invalid encrypted Commit", func(t *testing.T) {
		remote := validRemote.cloneObjects()
		remote.extraRefs = []AnnouncementRef{{Tag: validTag, Descriptor: validDescriptor}}
		invalidVerifier := commitVerifierFunc(func(context.Context, CommitAnnouncement, *VerificationBudget) (VerifiedCommit, error) {
			return VerifiedCommit{}, ErrInvalidCommitVerification
		})
		result := mustDiscover(t, fixture.announcement.WorkspaceID, remote, invalidVerifier)
		assertSingleRejection(t, result, RejectionInvalidCommit)
	})

	t.Run("verified Commit binding mismatch", func(t *testing.T) {
		remote := validRemote.cloneObjects()
		remote.extraRefs = []AnnouncementRef{{Tag: validTag, Descriptor: validDescriptor}}
		badVerifier := commitVerifierFunc(func(ctx context.Context, announcement CommitAnnouncement, budget *VerificationBudget) (VerifiedCommit, error) {
			verified, err := fixture.commits.VerifyCommit(ctx, announcement, budget)
			if err != nil {
				return VerifiedCommit{}, err
			}
			verified.WorkspaceID = mustUUID(t, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
			return verified, nil
		})
		result := mustDiscover(t, fixture.announcement.WorkspaceID, remote, badVerifier)
		assertSingleRejection(t, result, RejectionInvalidBinding)
	})
}

func TestRegistryOperationsPreserveCancellationAndTransportFailure(t *testing.T) {
	t.Parallel()

	fixture := newRegistryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Publish(ctx, newMemoryRemote(), fixture.local, PublicationClosure{}, fixture.announcement); !errors.Is(err, context.Canceled) {
		t.Fatalf("Publish(canceled) = %v, want context.Canceled", err)
	}
	if _, err := Discover(ctx, fixture.announcement.WorkspaceID, newMemoryRemote(), fixture.commits); !errors.Is(err, context.Canceled) {
		t.Fatalf("Discover(canceled) = %v, want context.Canceled", err)
	}

	remote := newMemoryRemote()
	remote.listErr = errors.New("registry unavailable")
	if _, err := Discover(context.Background(), fixture.announcement.WorkspaceID, remote, fixture.commits); err == nil {
		t.Fatal("Discover swallowed tag-list transport failure")
	}
}

func TestDiscoverAbortsOnMidstreamTransportFailureWithoutPartialFrontier(t *testing.T) {
	t.Parallel()

	fixture := newRegistryFixture(t)
	remote := newMemoryRemote()
	closure := PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}}
	if _, err := Publish(context.Background(), remote, fixture.local, closure, fixture.announcement); err != nil {
		t.Fatalf("publish valid sibling: %v", err)
	}

	sibling := fixture.announcement
	sibling.Signature = append([]byte(nil), sibling.Signature...)
	sibling.Signature[0] ^= 0x80
	siblingDescriptor, err := Publish(context.Background(), remote, fixture.local, closure, sibling)
	if err != nil {
		t.Fatalf("publish failing sibling: %v", err)
	}
	sentinel := errors.New("midstream registry transport failed")
	remote.readErr[siblingDescriptor.Digest] = sentinel

	discovery, err := Discover(context.Background(), fixture.announcement.WorkspaceID, remote, fixture.commits)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Discover error = %v, want transport sentinel", err)
	}
	if len(discovery.Announcements) != 0 || len(discovery.Rejections) != 0 || len(discovery.Inaccessible) != 0 {
		t.Fatalf("Discover returned a partial frontier: %#v", discovery)
	}
}

func TestRegistryOperationsPropagateCloseFailures(t *testing.T) {
	t.Parallel()

	t.Run("local publication source", func(t *testing.T) {
		fixture := newRegistryFixture(t)
		sentinel := errors.New("local close failed")
		fixture.local.closeErr[fixture.dependency.Digest] = sentinel
		remote := newMemoryRemote()
		_, err := Publish(
			context.Background(), remote, fixture.local,
			PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}},
			fixture.announcement,
		)
		if !errors.Is(err, sentinel) {
			t.Fatalf("Publish close error = %v, want sentinel", err)
		}
		page, listErr := remote.ListAnnouncements(context.Background(), "", discoveryPageSize, newVerificationBudget())
		if listErr != nil || len(page.Refs) != 0 {
			t.Fatalf("close failure became visible: %#v, %v", page, listErr)
		}
	})

	t.Run("remote verification source", func(t *testing.T) {
		fixture := newRegistryFixture(t)
		remote := fixture.local.cloneObjects()
		sentinel := errors.New("remote close failed")
		remote.closeErr[fixture.dependency.Digest] = sentinel
		_, err := Publish(
			context.Background(), remote, fixture.local,
			PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}},
			fixture.announcement,
		)
		if !errors.Is(err, sentinel) {
			t.Fatalf("Publish remote close error = %v, want sentinel", err)
		}
	})

	t.Run("discovery announcement source", func(t *testing.T) {
		fixture := newRegistryFixture(t)
		remote := newMemoryRemote()
		descriptor, err := Publish(
			context.Background(), remote, fixture.local,
			PublicationClosure{MaterialManifests: []artifact.Descriptor{fixture.dependency}},
			fixture.announcement,
		)
		if err != nil {
			t.Fatalf("Publish: %v", err)
		}
		sentinel := errors.New("announcement close failed")
		remote.closeErr[descriptor.Digest] = sentinel
		if _, err := Discover(context.Background(), fixture.announcement.WorkspaceID, remote, fixture.commits); !errors.Is(err, sentinel) {
			t.Fatalf("Discover close error = %v, want sentinel", err)
		}
	})
}

type registryFixture struct {
	signer       *artifact.DeviceIdentity
	enrollment   artifact.VerifiedDevice
	local        *memoryRemote
	dependency   artifact.Descriptor
	commit       artifact.Descriptor
	grant        artifact.Descriptor
	announcement CommitAnnouncement
	commits      commitVerifierFunc
}

func newRegistryFixture(t *testing.T) registryFixture {
	t.Helper()

	signer, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatalf("GenerateDeviceIdentity: %v", err)
	}
	assertion := []byte("signed-device-enrollment")
	claims := artifact.EnrollmentClaims{
		DeviceID:         signer.DeviceID(),
		Subject:          "github:user:1001",
		X25519Recipient:  signer.RecipientString(),
		Ed25519PublicKey: signer.SigningPublicKey(),
	}
	enrollment, err := artifact.VerifyEnrollment(context.Background(), enrollmentVerifierFunc(func(_ context.Context, got []byte) (artifact.EnrollmentClaims, error) {
		if !bytes.Equal(got, assertion) {
			return artifact.EnrollmentClaims{}, errors.New("unknown assertion")
		}
		return claims, nil
	}), assertion)
	if err != nil {
		t.Fatalf("VerifyEnrollment: %v", err)
	}

	enrollments := enrollmentVerifierFunc(func(_ context.Context, got []byte) (artifact.EnrollmentClaims, error) {
		if !bytes.Equal(got, assertion) {
			return artifact.EnrollmentClaims{}, errors.New("unknown assertion")
		}
		return claims, nil
	})
	local := newMemoryRemote()
	dependency := local.put(artifact.MediaTypeEncryptedMaterial, []byte("encrypted dependency"))
	grant := local.put(artifact.MediaTypeAccessGrant, []byte("encrypted Grant envelope"))
	commit := local.put(artifact.MediaTypeEncryptedCommit, []byte("encrypted signed Commit"))
	workspaceID := mustUUID(t, "11111111-1111-4111-8111-111111111111")
	root := artifact.SealedRef{Revision: digest.FromString("root revision"), Material: digest.FromString("root material"), Grant: digest.FromString("root grant")}
	policy := artifact.SealedRef{Revision: digest.FromString("policy revision"), Material: digest.FromString("policy material"), Grant: digest.FromString("policy grant")}
	value := commitmodel.Commit{
		APIVersion:  commitmodel.APIVersion,
		Kind:        commitmodel.Kind,
		WorkspaceID: workspaceID,
		Root:        root,
		Policy:      policy,
		Actor:       claims.Subject,
		DeviceID:    signer.DeviceID(),
		OperationID: mustUUID(t, "22222222-2222-4222-8222-222222222222"),
		Timestamp:   commitmodel.NewTimestamp(time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)),
		Provenance: []commitmodel.MutationProvenance{{
			ID:     mustUUID(t, "33333333-3333-4333-8333-333333333333"),
			Action: commitmodel.InitializeAction(),
			Target: mustUUID(t, "44444444-4444-4444-8444-444444444444"),
			After:  &root,
		}},
	}
	signed, err := commitmodel.SignCommit(value, signer, enrollment)
	if err != nil {
		t.Fatalf("SignCommit: %v", err)
	}
	verified, err := commitmodel.VerifySignedCommit(context.Background(), signed, enrollments)
	if err != nil {
		t.Fatalf("VerifySignedCommit: %v", err)
	}
	announcement, err := NewCommitAnnouncement(workspaceID, verified.Digest(), commit, grant, signer, enrollment)
	if err != nil {
		t.Fatalf("NewCommitAnnouncement: %v", err)
	}
	commits := commitVerifierFunc(func(ctx context.Context, got CommitAnnouncement, _ *VerificationBudget) (VerifiedCommit, error) {
		if err := VerifyCommitAnnouncement(ctx, got, signer.SigningPublicKey()); err != nil {
			return VerifiedCommit{}, err
		}
		return verifiedCommitFor(got, verified), nil
	})
	return registryFixture{
		signer:       signer,
		enrollment:   enrollment,
		local:        local,
		dependency:   dependency,
		commit:       commit,
		grant:        grant,
		announcement: announcement,
		commits:      commits,
	}
}

func verifiedCommitFor(announcement CommitAnnouncement, value commitmodel.VerifiedCommit) VerifiedCommit {
	return VerifiedCommit{
		CommitID:          announcement.CommitID,
		WorkspaceID:       announcement.WorkspaceID,
		CommitSignerKeyID: value.SignerKeyID(),
		EncryptedCommit:   announcement.EncryptedCommit,
		Grant:             announcement.Grant,
		Value:             value,
	}
}

type enrollmentVerifierFunc func(context.Context, []byte) (artifact.EnrollmentClaims, error)

func (f enrollmentVerifierFunc) VerifyEnrollment(ctx context.Context, assertion []byte) (artifact.EnrollmentClaims, error) {
	return f(ctx, assertion)
}

type commitVerifierFunc func(context.Context, CommitAnnouncement, *VerificationBudget) (VerifiedCommit, error)

func (f commitVerifierFunc) VerifyCommit(ctx context.Context, announcement CommitAnnouncement, budget *VerificationBudget) (VerifiedCommit, error) {
	return f(ctx, announcement, budget)
}

type announcementIndexFunc func(context.Context, string, int, *VerificationBudget) (AnnouncementPage, error)

func (f announcementIndexFunc) PublishAnnouncement(context.Context, string, artifact.Descriptor, []artifact.Descriptor) error {
	return errors.New("unexpected publication")
}

func (f announcementIndexFunc) ListAnnouncements(ctx context.Context, cursor string, limit int, budget *VerificationBudget) (AnnouncementPage, error) {
	return f(ctx, cursor, limit, budget)
}

type memoryObject struct {
	descriptor artifact.Descriptor
	data       []byte
}

type memoryAnnouncement struct {
	descriptor artifact.Descriptor
	retained   []artifact.Descriptor
}

type memoryRemote struct {
	mu            sync.Mutex
	objects       map[digest.Digest]memoryObject
	announcements map[string]memoryAnnouncement
	extraRefs     []AnnouncementRef
	failPush      map[digest.Digest]error
	failOpen      map[digest.Digest]error
	readErr       map[digest.Digest]error
	closeErr      map[digest.Digest]error
	failTag       error
	listErr       error
	events        []string
}

func newMemoryRemote() *memoryRemote {
	return &memoryRemote{
		objects:       make(map[digest.Digest]memoryObject),
		announcements: make(map[string]memoryAnnouncement),
		failPush:      make(map[digest.Digest]error),
		failOpen:      make(map[digest.Digest]error),
		readErr:       make(map[digest.Digest]error),
		closeErr:      make(map[digest.Digest]error),
	}
}

func (m *memoryRemote) Ingest(ctx context.Context, mediaType string, reader io.Reader) (artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	descriptor := descriptorFor(mediaType, data)
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.objects[descriptor.Digest]; ok &&
		(existing.descriptor != descriptor || !bytes.Equal(existing.data, data)) {
		return artifact.Descriptor{}, ErrInvalidRemoteObject
	}
	m.objects[descriptor.Digest] = memoryObject{descriptor: descriptor, data: append([]byte(nil), data...)}
	return descriptor, nil
}

func (m *memoryRemote) put(mediaType string, data []byte) artifact.Descriptor {
	descriptor := descriptorFor(mediaType, data)
	m.objects[descriptor.Digest] = memoryObject{descriptor: descriptor, data: append([]byte(nil), data...)}
	return descriptor
}

func (m *memoryRemote) Push(ctx context.Context, expected artifact.Descriptor, reader io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	actual := descriptorFor(expected.MediaType, data)
	if actual != expected {
		return ErrInvalidRemoteObject
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failPush[expected.Digest]; err != nil {
		return err
	}
	if existing, ok := m.objects[expected.Digest]; ok {
		if existing.descriptor != expected || !bytes.Equal(existing.data, data) {
			return ErrInvalidRemoteObject
		}
		return nil
	}
	m.objects[expected.Digest] = memoryObject{descriptor: expected, data: append([]byte(nil), data...)}
	m.events = append(m.events, "push:"+expected.Digest.String())
	return nil
}

func (m *memoryRemote) Open(ctx context.Context, objectDigest digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failOpen[objectDigest]; err != nil {
		return nil, artifact.Descriptor{}, err
	}
	object, ok := m.objects[objectDigest]
	if !ok {
		return nil, artifact.Descriptor{}, ErrObjectNotFound
	}
	data := append([]byte(nil), object.data...)
	var reader io.Reader = bytes.NewReader(data)
	if readErr := m.readErr[objectDigest]; readErr != nil {
		reader = &midstreamErrorReader{data: data, err: readErr}
	}
	return &closeErrorReadCloser{
		Reader: reader,
		err:    m.closeErr[objectDigest],
	}, object.descriptor, nil
}

func (m *memoryRemote) OpenExpected(ctx context.Context, expected artifact.Descriptor) (io.ReadCloser, error) {
	reader, descriptor, err := m.Open(ctx, expected.Digest)
	if err != nil {
		return nil, err
	}
	if descriptor != expected {
		_ = reader.Close()
		return nil, ErrInvalidRemoteObject
	}
	return reader, nil
}

func (m *memoryRemote) Has(ctx context.Context, objectDigest digest.Digest) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objects[objectDigest]
	return ok, nil
}

func (m *memoryRemote) PublishAnnouncement(ctx context.Context, tag string, descriptor artifact.Descriptor, retained []artifact.Descriptor) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	wantTag, err := AnnouncementTag(descriptor.Digest)
	if err != nil || tag != wantTag {
		return ErrInvalidAnnouncement
	}
	canonicalRetained := append([]artifact.Descriptor(nil), retained...)
	sort.Slice(canonicalRetained, func(i, j int) bool { return canonicalRetained[i].Digest < canonicalRetained[j].Digest })
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failTag != nil {
		return m.failTag
	}
	if _, ok := m.objects[descriptor.Digest]; !ok {
		return ErrObjectNotFound
	}
	if existing, ok := m.announcements[tag]; ok {
		if existing.descriptor != descriptor || !descriptorsEqual(existing.retained, canonicalRetained) {
			return ErrAnnouncementConflict
		}
		return nil
	}
	m.announcements[tag] = memoryAnnouncement{descriptor: descriptor, retained: canonicalRetained}
	m.events = append(m.events, "tag:"+tag)
	return nil
}

func (m *memoryRemote) ListAnnouncements(ctx context.Context, cursor string, limit int, _ *VerificationBudget) (AnnouncementPage, error) {
	if err := ctx.Err(); err != nil {
		return AnnouncementPage{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return AnnouncementPage{}, m.listErr
	}
	if limit <= 0 {
		return AnnouncementPage{}, errors.New("invalid page limit")
	}
	refs := append([]AnnouncementRef(nil), m.extraRefs...)
	for tag, announcement := range m.announcements {
		refs = append(refs, AnnouncementRef{Tag: tag, Descriptor: announcement.descriptor})
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Tag == refs[j].Tag {
			return refs[i].Descriptor.Digest < refs[j].Descriptor.Digest
		}
		return refs[i].Tag < refs[j].Tag
	})
	start := 0
	if cursor != "" {
		parsed, err := strconv.Atoi(cursor)
		if err != nil || parsed < 0 || parsed > len(refs) {
			return AnnouncementPage{}, errors.New("invalid cursor")
		}
		start = parsed
	}
	end := min(start+limit, len(refs))
	page := AnnouncementPage{Refs: append([]AnnouncementRef(nil), refs[start:end]...)}
	if end < len(refs) {
		page.Next = strconv.Itoa(end)
	}
	return page, nil
}

func (m *memoryRemote) cloneObjects() *memoryRemote {
	clone := newMemoryRemote()
	m.mu.Lock()
	defer m.mu.Unlock()
	for objectDigest, object := range m.objects {
		object.data = append([]byte(nil), object.data...)
		clone.objects[objectDigest] = object
	}
	return clone
}

func descriptorFor(mediaType string, data []byte) artifact.Descriptor {
	return artifact.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
}

type closeErrorReadCloser struct {
	io.Reader
	err error
}

func (r *closeErrorReadCloser) Close() error { return r.err }

type midstreamErrorReader struct {
	data []byte
	err  error
	sent bool
}

func (r *midstreamErrorReader) Read(destination []byte) (int, error) {
	if r.sent {
		return 0, r.err
	}
	if len(r.data) == 0 {
		return 0, r.err
	}
	r.sent = true
	limit := min(len(destination), max(1, len(r.data)/2))
	return copy(destination, r.data[:limit]), nil
}

func descriptorsEqual(left, right []artifact.Descriptor) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func eventIndex(events []string, want string) int {
	for i, event := range events {
		if event == want {
			return i
		}
	}
	return -1
}

func mustUUID(t *testing.T, value string) artifact.UUID {
	t.Helper()
	parsed, err := artifact.ParseUUID(value)
	if err != nil {
		t.Fatalf("ParseUUID(%q): %v", value, err)
	}
	return parsed
}

func mustDiscover(t *testing.T, workspaceID artifact.UUID, remote Remote, commits CommitVerifier) Discovery {
	t.Helper()
	result, err := Discover(context.Background(), workspaceID, remote, commits)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return result
}

func assertSingleRejection(t *testing.T, result Discovery, code RejectionCode) {
	t.Helper()
	if len(result.Announcements) != 0 || len(result.Rejections) != 1 || result.Rejections[0].Code != code {
		t.Fatalf("Discovery = %#v, want one %s rejection", result, code)
	}
}

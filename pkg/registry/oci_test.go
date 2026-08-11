package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/errdef"
)

func TestOCIRemotePublishesDeterministicIndexLast(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)

	announcement, err := Publish(context.Background(), remote, fixture.local, publicationClosure(fixture.dependency), fixture.announcement)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	tag, _ := AnnouncementTag(announcement.Digest)
	indexDescriptor, err := target.Resolve(context.Background(), tag)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	indexBytes := fetchTargetBytes(t, target, indexDescriptor)
	index, bootstrapDescriptor, shardDescriptors, err := decodeAndValidateOCIAnnouncementIndex(indexBytes)
	if err != nil {
		t.Fatalf("decode index: %v", err)
	}
	bootstrapBytes := fetchTargetBytes(t, target, bootstrapDescriptor)
	bootstrap, decodedAnnouncement, bootstrapRetained, err := decodeAndValidateOCIAnnouncementBootstrapManifest(bootstrapBytes)
	if err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	if decodedAnnouncement != announcement {
		t.Fatalf("announcement layer = %#v, want %#v", decodedAnnouncement, announcement)
	}
	if index.ArtifactType != OCIAnnouncementArtifactType || bootstrap.ArtifactType != OCIAnnouncementBootstrapArtifactType ||
		bootstrap.Config.MediaType != OCIAnnouncementConfigMediaType {
		t.Fatalf("index/bootstrap/config types = %q / %q / %q", index.ArtifactType, bootstrap.ArtifactType, bootstrap.Config.MediaType)
	}
	if index.Annotations != nil || bootstrap.Annotations != nil || bytes.Contains(indexBytes, []byte("annotations")) ||
		bytes.Contains(bootstrapBytes, []byte("annotations")) {
		t.Fatal("public OCI metadata contains annotations")
	}
	if len(bootstrap.Layers) != 3 || len(bootstrapRetained) != 2 {
		t.Fatalf("bootstrap = %#v, want announcement plus Grant and Commit", bootstrap)
	}
	if len(shardDescriptors) != 1 {
		t.Fatalf("retention shard count = %d, want 1", len(shardDescriptors))
	}
	shard, retained, err := decodeAndValidateOCIRetentionShardManifest(fetchTargetBytes(t, target, shardDescriptors[0]))
	if err != nil {
		t.Fatalf("decode retention shard: %v", err)
	}
	if shard.ArtifactType != OCIRetentionShardArtifactType || len(retained) != 1 || retained[0] != fixture.dependency {
		t.Fatalf("retention shard = %#v / %#v", shard, retained)
	}

	events := target.snapshotEvents()
	manifestPush := eventIndex(events, "push:"+ocispec.MediaTypeImageManifest)
	indexPush := eventIndex(events, "push:"+ocispec.MediaTypeImageIndex)
	configPush := eventIndex(events, "push:"+OCIAnnouncementConfigMediaType)
	tagEvent := eventIndex(events, "tag:"+tag)
	if configPush < 0 || manifestPush <= configPush || indexPush <= manifestPush || tagEvent <= indexPush {
		t.Fatalf("OCI publication order = %v", events)
	}
	for _, descriptor := range []artifact.Descriptor{fixture.dependency, fixture.grant, fixture.commit, announcement} {
		if index := eventIndex(events, "push:"+descriptor.MediaType); index < 0 || index >= configPush {
			t.Fatalf("object %s not pushed before config/manifest/tag: %v", descriptor.Digest, events)
		}
	}

	// Input order is not wire order, so an honest repeat is byte-identical and
	// does not reapply the mutable tag.
	retained = []artifact.Descriptor{fixture.commit, fixture.grant, fixture.dependency}
	if err := remote.PublishAnnouncement(context.Background(), tag, announcement, retained); err != nil {
		t.Fatalf("idempotent PublishAnnouncement() error = %v", err)
	}
	if got := target.eventCount("tag:" + tag); got != 1 {
		t.Fatalf("tag applications = %d, want 1", got)
	}
}

func TestOCIRemoteListRegistersOnlyVerifiedBootstrapDescriptors(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	publisher := mustOCIRemote(t, target)
	announcement, err := Publish(context.Background(), publisher, fixture.local, publicationClosure(fixture.dependency), fixture.announcement)
	if err != nil {
		t.Fatal(err)
	}
	poison := fixture.dependency
	poison.MediaType = "application/vnd.attacker.poison"
	_, _, bootstrapDescriptor, err := buildOCIAnnouncementBootstrapManifest(
		announcement, []artifact.Descriptor{fixture.grant, fixture.commit},
	)
	if err != nil {
		t.Fatal(err)
	}
	poisonShard := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: OCIRetentionShardArtifactType,
		Config:       ociAnnouncementConfigDescriptor(),
		Layers:       []ocispec.Descriptor{toOCIDescriptor(poison)},
	}
	poisonShardBytes, poisonShardDescriptor, err := encodeOCIManifest(poisonShard, "hostile retention shard")
	if err != nil {
		t.Fatal(err)
	}
	_, indexBytes, indexDescriptor, err := buildOCIAnnouncementIndex(bootstrapDescriptor, []ocispec.Descriptor{poisonShardDescriptor})
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range []struct {
		descriptor ocispec.Descriptor
		encoded    []byte
	}{
		{descriptor: poisonShardDescriptor, encoded: poisonShardBytes},
		{descriptor: indexDescriptor, encoded: indexBytes},
	} {
		if err := target.Push(context.Background(), object.descriptor, bytes.NewReader(object.encoded)); err != nil {
			t.Fatal(err)
		}
	}
	tag, _ := AnnouncementTag(announcement.Digest)
	target.setTag(tag, indexDescriptor)

	reader := mustOCIRemote(t, target)
	page, err := reader.ListAnnouncements(context.Background(), "", 10, newVerificationBudget())
	if err != nil {
		t.Fatalf("ListAnnouncements() error = %v", err)
	}
	if len(page.Refs) != 1 || page.Refs[0].Descriptor != announcement || page.Next != "" {
		t.Fatalf("page = %#v", page)
	}
	bootstrap := []artifact.Descriptor{announcement, fixture.grant, fixture.commit}
	for _, descriptor := range bootstrap {
		has, err := reader.Has(context.Background(), descriptor.Digest)
		if err != nil || has {
			t.Fatalf("listing-derived Has(%s) = %v, %v", descriptor.Digest, has, err)
		}
		stream, err := reader.OpenExpected(context.Background(), descriptor)
		if err != nil {
			t.Fatalf("OpenExpected(%s) error = %v", descriptor.Digest, err)
		}
		if _, err := io.Copy(io.Discard, stream); err != nil {
			t.Fatalf("read %s: %v", descriptor.Digest, err)
		}
		if err := stream.Close(); err != nil {
			t.Fatalf("close %s: %v", descriptor.Digest, err)
		}
	}
	has, err := reader.Has(context.Background(), fixture.dependency.Digest)
	if err != nil || has {
		t.Fatalf("unauthenticated retained dependency Has() = %v, %v", has, err)
	}
	if _, _, err := reader.Open(context.Background(), fixture.dependency.Digest); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("unauthenticated retained dependency Open() error = %v, want ErrObjectNotFound", err)
	}
	trusted := append(bootstrap, fixture.dependency)
	if err := reader.RegisterVerifiedDescriptors(context.Background(), trusted); err != nil {
		t.Fatalf("RegisterVerifiedDescriptors() error = %v", err)
	}
	for _, descriptor := range trusted {
		if has, err := reader.Has(context.Background(), descriptor.Digest); err != nil || !has {
			t.Fatalf("registered descriptor %s Has() = %v, %v", descriptor.Digest, has, err)
		}
	}
}

func TestOCIRemoteAuthenticatedRetentionCrossMediaClaimsFailClosed(t *testing.T) {
	t.Parallel()
	data := []byte("identical retained bytes")
	grant := descriptorFor(artifact.MediaTypeAccessGrant, data)
	material := descriptorFor(artifact.MediaTypeEncryptedMaterial, data)
	target := newTestOCITarget()
	for _, descriptor := range []artifact.Descriptor{grant, material} {
		if err := target.Push(context.Background(), toOCIDescriptor(descriptor), bytes.NewReader(data)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			t.Fatal(err)
		}
	}
	remote := mustOCIRemote(t, target)
	if err := remote.rememberRetainedDescriptors([]artifact.Descriptor{grant}); err != nil {
		t.Fatal(err)
	}
	if err := remote.rememberRetainedDescriptors([]artifact.Descriptor{material}); err != nil {
		t.Fatal(err)
	}

	if _, _, err := remote.Open(context.Background(), grant.Digest); !errors.Is(err, ErrInvalidRemoteObject) {
		t.Fatalf("ambiguous retained Open() error = %v", err)
	}
	if _, err := remote.Has(context.Background(), grant.Digest); !errors.Is(err, ErrInvalidRemoteObject) {
		t.Fatalf("ambiguous retained Has() error = %v", err)
	}
	for _, descriptor := range []artifact.Descriptor{grant, material} {
		reader, err := remote.OpenExpected(context.Background(), descriptor)
		if err != nil {
			t.Fatalf("OpenExpected(%s) error = %v", descriptor.MediaType, err)
		}
		if _, err := io.Copy(io.Discard, reader); err != nil {
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOCIRemoteAnnouncementPaginationIsBoundedAndDeterministic(t *testing.T) {
	t.Parallel()
	target := newTestOCITarget()
	target.additionalTags = []string{"latest", "commit-c", "commit-a", "head", "commit-b"}
	remote := mustOCIRemote(t, target)

	first, err := remote.ListAnnouncements(context.Background(), "", 2, newVerificationBudget())
	if err != nil {
		t.Fatal(err)
	}
	if got := announcementRefTags(first.Refs); !equalStrings(got, []string{"commit-a", "commit-b"}) {
		t.Fatalf("first page tags = %v", got)
	}
	if first.Next == "" {
		t.Fatal("first page has no continuation cursor")
	}
	second, err := remote.ListAnnouncements(context.Background(), first.Next, 2, newVerificationBudget())
	if err != nil {
		t.Fatal(err)
	}
	if got := announcementRefTags(second.Refs); !equalStrings(got, []string{"commit-c"}) {
		t.Fatalf("second page tags = %v", got)
	}
	if second.Next != "" {
		t.Fatalf("final cursor = %q, want empty", second.Next)
	}

	exact, err := remote.ListAnnouncements(context.Background(), "", 3, newVerificationBudget())
	if err != nil {
		t.Fatal(err)
	}
	if len(exact.Refs) != 3 || exact.Next != "" {
		t.Fatalf("exact-size page = %#v", exact)
	}
}

func TestOCIRemoteEarlierCrossMediaAnnouncementCannotPoisonExactFetch(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	sharedBytes := []byte("same immutable bytes under hostile cross-media labels")
	sharedGrant := descriptorFor(artifact.MediaTypeAccessGrant, sharedBytes)
	sharedCommit := descriptorFor(artifact.MediaTypeEncryptedCommit, sharedBytes)
	otherGrantBytes := []byte("other Grant")
	otherCommitBytes := []byte("other encrypted Commit")
	otherGrant := descriptorFor(artifact.MediaTypeAccessGrant, otherGrantBytes)
	otherCommit := descriptorFor(artifact.MediaTypeEncryptedCommit, otherCommitBytes)

	var (
		grantAnnouncement, commitAnnouncement CommitAnnouncement
		grantBytes, commitBytes               []byte
		grantDescriptor, commitDescriptor     artifact.Descriptor
		grantTag, commitTag                   string
		foundLexicallyEarlierGrant            bool
	)
	for nonce := 0; nonce < 128; nonce++ {
		var err error
		grantAnnouncement, err = NewCommitAnnouncement(
			fixture.announcement.WorkspaceID,
			digest.FromString(fmt.Sprintf("grant-labelled-%d", nonce)),
			otherCommit,
			sharedGrant,
			fixture.signer,
			fixture.enrollment,
		)
		if err != nil {
			t.Fatal(err)
		}
		commitAnnouncement, err = NewCommitAnnouncement(
			fixture.announcement.WorkspaceID,
			digest.FromString(fmt.Sprintf("commit-labelled-%d", nonce)),
			sharedCommit,
			otherGrant,
			fixture.signer,
			fixture.enrollment,
		)
		if err != nil {
			t.Fatal(err)
		}
		grantBytes, err = EncodeCommitAnnouncement(grantAnnouncement)
		if err != nil {
			t.Fatal(err)
		}
		commitBytes, err = EncodeCommitAnnouncement(commitAnnouncement)
		if err != nil {
			t.Fatal(err)
		}
		grantDescriptor = descriptorFor(artifact.MediaTypeCommitAnnouncement, grantBytes)
		commitDescriptor = descriptorFor(artifact.MediaTypeCommitAnnouncement, commitBytes)
		grantTag, _ = AnnouncementTag(grantDescriptor.Digest)
		commitTag, _ = AnnouncementTag(commitDescriptor.Digest)
		if grantTag < commitTag {
			foundLexicallyEarlierGrant = true
			break
		}
	}
	if !foundLexicallyEarlierGrant {
		t.Fatal("failed to construct lexically earlier Grant-labelled announcement")
	}

	target := newTestOCITarget()
	for _, object := range []struct {
		descriptor artifact.Descriptor
		data       []byte
	}{
		{sharedGrant, sharedBytes},
		{sharedCommit, sharedBytes},
		{otherGrant, otherGrantBytes},
		{otherCommit, otherCommitBytes},
		{grantDescriptor, grantBytes},
		{commitDescriptor, commitBytes},
	} {
		if err := target.Push(context.Background(), toOCIDescriptor(object.descriptor), bytes.NewReader(object.data)); err != nil {
			t.Fatal(err)
		}
	}
	publishRawOCIAnnouncement(t, target, grantTag, grantDescriptor, []artifact.Descriptor{sharedGrant, otherCommit})
	publishRawOCIAnnouncement(t, target, commitTag, commitDescriptor, []artifact.Descriptor{otherGrant, sharedCommit})

	remote := mustOCIRemote(t, target)
	page, err := remote.ListAnnouncements(context.Background(), "", 10, newVerificationBudget())
	if err != nil {
		t.Fatal(err)
	}
	if got := announcementRefTags(page.Refs); !equalStrings(got, []string{grantTag, commitTag}) {
		t.Fatalf("cross-media refs = %v", got)
	}
	if has, err := remote.Has(context.Background(), sharedGrant.Digest); err != nil || has {
		t.Fatalf("listing polluted digest cache: Has() = %v, %v", has, err)
	}
	for _, descriptor := range []artifact.Descriptor{sharedGrant, sharedCommit} {
		reader, err := remote.OpenExpected(context.Background(), descriptor)
		if err != nil {
			t.Fatalf("OpenExpected(%s) error = %v", descriptor.MediaType, err)
		}
		got, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, sharedBytes) {
			t.Fatalf("OpenExpected(%s) returned wrong bytes", descriptor.MediaType)
		}
	}
}

func TestOCIRemoteAnnouncementPaginationRejectsInvalidOrNonProgressingState(t *testing.T) {
	t.Parallel()
	base := newTestOCITarget()
	remote := mustOCIRemote(t, base)
	for _, test := range []struct {
		name   string
		cursor string
		limit  int
	}{
		{name: "invalid cursor", cursor: "not-an-oci-cursor", limit: 1},
		{name: "zero limit", limit: 0},
		{name: "oversized limit", limit: MaxOCIAnnouncementPageSize + 1},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if _, err := remote.ListAnnouncements(context.Background(), test.cursor, test.limit, newVerificationBudget()); !errors.Is(err, errInvalidOCITagListing) {
				t.Fatalf("ListAnnouncements() error = %v, want tag-listing protocol error", err)
			}
		})
	}

	last := "commit-a"
	nonProgressing := mustOCIRemote(t, &scriptedTagsOCITarget{
		testOCITarget: newTestOCITarget(),
		pages:         [][]string{{last}},
	})
	if _, err := nonProgressing.ListAnnouncements(context.Background(), encodeOCIAnnouncementCursor(last), 1, newVerificationBudget()); !errors.Is(err, errInvalidOCITagListing) {
		t.Fatalf("non-progressing ListAnnouncements() error = %v", err)
	}

	unsorted := mustOCIRemote(t, &scriptedTagsOCITarget{
		testOCITarget: newTestOCITarget(),
		pages:         [][]string{{"commit-b", "commit-a"}},
	})
	if _, err := unsorted.ListAnnouncements(context.Background(), "", 2, newVerificationBudget()); !errors.Is(err, errInvalidOCITagListing) {
		t.Fatalf("unsorted ListAnnouncements() error = %v", err)
	}
}

func TestOCIRemoteAnnouncementCursorBoundsRawUnrelatedTagTraversal(t *testing.T) {
	t.Parallel()
	target := newTestOCITarget()
	target.additionalTags = make([]string, 0, MaxOCIRawTagsPerPage+2)
	target.additionalTags = append(target.additionalTags, "commit-a")
	for index := 0; index <= MaxOCIRawTagsPerPage; index++ {
		target.additionalTags = append(target.additionalTags, fmt.Sprintf("d-%05d", index))
	}
	remote := mustOCIRemote(t, target)
	budget := newVerificationBudget()

	first, err := remote.ListAnnouncements(context.Background(), "", 1, budget)
	if err != nil {
		t.Fatal(err)
	}
	if got := announcementRefTags(first.Refs); !equalStrings(got, []string{"commit-a"}) || first.Next == "" {
		t.Fatalf("first bounded raw page = %#v", first)
	}
	rawLast, err := decodeOCIAnnouncementCursor(first.Next)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(rawLast, announcementTagPrefix) {
		t.Fatalf("cursor %q did not preserve unrelated raw traversal", rawLast)
	}
	final, err := remote.ListAnnouncements(context.Background(), first.Next, 1, budget)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Refs) != 0 || final.Next != "" {
		t.Fatalf("final raw traversal page = %#v", final)
	}

	onlyUnrelated := newTestOCITarget()
	onlyUnrelated.additionalTags = append([]string(nil), target.additionalTags[1:]...)
	if _, err := mustOCIRemote(t, onlyUnrelated).ListAnnouncements(
		context.Background(), "", 1, newVerificationBudget(),
	); !errors.Is(err, ErrDiscoveryBudgetExceeded) {
		t.Fatalf("underfilled raw-tag flood error = %v, want ErrDiscoveryBudgetExceeded", err)
	}
}

func TestOCIRemoteObjectPushIsStreamingVerifiedAndIdempotent(t *testing.T) {
	t.Parallel()
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)
	data := bytes.Repeat([]byte("streamed OCI object"), 20_000)
	descriptor := descriptorFor(artifact.MediaTypeEncryptedChunk, data)

	if err := remote.Push(context.Background(), descriptor, &boundedOCIReader{source: bytes.NewReader(data), maximum: 1024 * 1024}); err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	if err := remote.Push(context.Background(), descriptor, bytes.NewReader(data)); err != nil {
		t.Fatalf("idempotent Push() error = %v", err)
	}
	conflict := descriptor
	conflict.MediaType = "application/octet-stream"
	if err := remote.Push(context.Background(), conflict, bytes.NewReader(data)); !errors.Is(err, ErrInvalidRemoteObject) {
		t.Fatalf("conflicting Push() error = %v, want ErrInvalidRemoteObject", err)
	}

	stream, opened, err := remote.Open(context.Background(), descriptor.Digest)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if opened != descriptor || !bytes.Equal(got, data) {
		t.Fatal("opened OCI object differs")
	}
}

func TestOCIRemoteRejectsNonCanonicalAnnouncementBeforeTag(t *testing.T) {
	t.Parallel()
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)
	invalid := []byte{0xa0}
	descriptor := descriptorFor(artifact.MediaTypeCommitAnnouncement, invalid)
	if err := remote.Push(context.Background(), descriptor, bytes.NewReader(invalid)); err != nil {
		t.Fatal(err)
	}
	tag, _ := AnnouncementTag(descriptor.Digest)
	if err := remote.PublishAnnouncement(context.Background(), tag, descriptor, nil); !errors.Is(err, ErrInvalidAnnouncement) {
		t.Fatalf("PublishAnnouncement() error = %v, want ErrInvalidAnnouncement", err)
	}
	if target.hasTag(tag) {
		t.Fatal("invalid canonical announcement became visible")
	}
}

func TestOCIRemoteExistingTagMustBeIdentical(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)
	announcement, err := Publish(context.Background(), remote, fixture.local, publicationClosure(fixture.dependency), fixture.announcement)
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := AnnouncementTag(announcement.Digest)
	original, _ := target.Resolve(context.Background(), tag)

	extraBytes := []byte("additional retained ciphertext")
	extra := descriptorFor(artifact.MediaTypeEncryptedChunk, extraBytes)
	if err := remote.Push(context.Background(), extra, bytes.NewReader(extraBytes)); err != nil {
		t.Fatal(err)
	}
	maliciousDescriptor := publishRawOCIAnnouncement(
		t, target, tag, announcement,
		[]artifact.Descriptor{fixture.dependency, fixture.grant, fixture.commit, extra},
	)

	retained := []artifact.Descriptor{fixture.dependency, fixture.grant, fixture.commit}
	if err := remote.PublishAnnouncement(context.Background(), tag, announcement, retained); !errors.Is(err, ErrAnnouncementConflict) {
		t.Fatalf("PublishAnnouncement() error = %v, want ErrAnnouncementConflict", err)
	}
	got, _ := target.Resolve(context.Background(), tag)
	if !bareOCIDescriptorsEqual(got, maliciousDescriptor) || bareOCIDescriptorsEqual(got, original) {
		t.Fatal("conflicting existing tag was overwritten")
	}
}

func TestOCIRemotePostTagValidationDetectsMutation(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)
	announcement, err := Publish(context.Background(), remote, fixture.local, publicationClosure(fixture.dependency), fixture.announcement)
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := AnnouncementTag(announcement.Digest)

	extraBytes := []byte("post-tag mutation")
	extra := descriptorFor(artifact.MediaTypeEncryptedChunk, extraBytes)
	if err := remote.Push(context.Background(), extra, bytes.NewReader(extraBytes)); err != nil {
		t.Fatal(err)
	}
	maliciousDescriptor := publishRawOCIAnnouncement(
		t, target, tag, announcement,
		[]artifact.Descriptor{fixture.dependency, fixture.grant, fixture.commit, extra},
	)
	target.deleteTag(tag)
	target.setAfterTag(func(installed string) {
		if installed == tag {
			target.setTag(tag, maliciousDescriptor)
		}
	})

	retained := []artifact.Descriptor{fixture.dependency, fixture.grant, fixture.commit}
	if err := remote.PublishAnnouncement(context.Background(), tag, announcement, retained); !errors.Is(err, ErrAnnouncementConflict) {
		t.Fatalf("PublishAnnouncement() error = %v, want ErrAnnouncementConflict", err)
	}
}

func TestOCIRemoteCancellationAfterTagReportsVisibleSuccess(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)
	ctx, cancel := context.WithCancel(context.Background())
	target.setAfterTag(func(string) { cancel() })

	announcement, err := Publish(ctx, remote, fixture.local, publicationClosure(fixture.dependency), fixture.announcement)
	if err != nil {
		t.Fatalf("Publish() after successful visibility point = %v", err)
	}
	tag, _ := AnnouncementTag(announcement.Digest)
	if !target.hasTag(tag) {
		t.Fatal("successful publication tag is not visible")
	}
}

func TestOCIRemoteMalformedManifestIsIndependentDiscoveryRejection(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)
	if _, err := Publish(context.Background(), remote, fixture.local, publicationClosure(fixture.dependency), fixture.announcement); err != nil {
		t.Fatal(err)
	}

	fakeAnnouncementBytes := []byte("not a canonical announcement")
	fakeAnnouncement := descriptorFor(artifact.MediaTypeCommitAnnouncement, fakeAnnouncementBytes)
	if err := target.Push(context.Background(), toOCIDescriptor(fakeAnnouncement), bytes.NewReader(fakeAnnouncementBytes)); err != nil {
		t.Fatal(err)
	}
	badManifest := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.attacker.invalid",
		Config:       ociAnnouncementConfigDescriptor(),
		Layers:       []ocispec.Descriptor{toOCIDescriptor(fakeAnnouncement)},
	}
	badBytes, _ := json.Marshal(badManifest)
	badDescriptor := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(badBytes), Size: int64(len(badBytes))}
	if err := target.Push(context.Background(), badDescriptor, bytes.NewReader(badBytes)); err != nil {
		t.Fatal(err)
	}
	badTag, _ := AnnouncementTag(fakeAnnouncement.Digest)
	target.setTag(badTag, badDescriptor)

	result, err := Discover(context.Background(), fixture.announcement.WorkspaceID, remote, fixture.commits)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(result.Announcements) != 1 || len(result.Rejections) != 1 || result.Rejections[0].Tag != badTag {
		t.Fatalf("Discovery = %#v", result)
	}
}

func TestOCIRemoteAnnouncementLayerSizeFailuresAreIndependentRejections(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*ocispec.Manifest)
	}{
		{name: "wrong size", mutate: func(manifest *ocispec.Manifest) { manifest.Layers[0].Size++ }},
		{name: "oversize", mutate: func(manifest *ocispec.Manifest) { manifest.Layers[0].Size = MaxAnnouncementBytes + 1 }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRegistryFixture(t)
			target := newTestOCITarget()
			publisher := mustOCIRemote(t, target)
			announcement, err := Publish(
				context.Background(), publisher, fixture.local, publicationClosure(fixture.dependency), fixture.announcement,
			)
			if err != nil {
				t.Fatal(err)
			}
			tag, _ := AnnouncementTag(announcement.Digest)
			original, err := target.Resolve(context.Background(), tag)
			if err != nil {
				t.Fatal(err)
			}
			var index ocispec.Index
			if err := json.Unmarshal(fetchTargetBytes(t, target, original), &index); err != nil {
				t.Fatal(err)
			}
			var manifest ocispec.Manifest
			if err := json.Unmarshal(fetchTargetBytes(t, target, index.Manifests[0]), &manifest); err != nil {
				t.Fatal(err)
			}
			test.mutate(&manifest)
			encodedBootstrap, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			malformedBootstrap := ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromBytes(encodedBootstrap),
				Size:      int64(len(encodedBootstrap)),
			}
			if err := target.Push(context.Background(), malformedBootstrap, bytes.NewReader(encodedBootstrap)); err != nil {
				t.Fatal(err)
			}
			index.Manifests[0] = malformedBootstrap
			encodedIndex, err := json.Marshal(index)
			if err != nil {
				t.Fatal(err)
			}
			malformed := ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageIndex,
				Digest:    digest.FromBytes(encodedIndex),
				Size:      int64(len(encodedIndex)),
			}
			if err := target.Push(context.Background(), malformed, bytes.NewReader(encodedIndex)); err != nil {
				t.Fatal(err)
			}
			target.setTag(tag, malformed)

			page, err := mustOCIRemote(t, target).ListAnnouncements(
				context.Background(), "", 10, newVerificationBudget(),
			)
			if err != nil {
				t.Fatalf("ListAnnouncements() operational error = %v", err)
			}
			if len(page.Refs) != 1 || page.Refs[0].Descriptor != fromOCIDescriptor(malformed) {
				t.Fatalf("hostile entry ref = %#v", page.Refs)
			}
		})
	}
}

func TestOCIRemoteAnnouncementBodyReadFailuresRemainOperational(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	publisher := mustOCIRemote(t, target)
	announcement, err := Publish(
		context.Background(), publisher, fixture.local, publicationClosure(fixture.dependency), fixture.announcement,
	)
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := AnnouncementTag(announcement.Digest)
	manifest, err := target.Resolve(context.Background(), tag)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := fetchTargetBytes(t, target, manifest)
	announcementBytes, err := EncodeCommitAnnouncement(fixture.announcement)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		descriptor ocispec.Descriptor
		prefix     []byte
	}{
		{name: "manifest body", descriptor: manifest, prefix: manifestBytes[:min(8, len(manifestBytes))]},
		{name: "announcement body", descriptor: toOCIDescriptor(announcement), prefix: announcementBytes[:min(8, len(announcementBytes))]},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			transportErr := errors.New("injected response body failure")
			failing := &bodyFailingOCITarget{
				testOCITarget: target,
				digest:        test.descriptor.Digest,
				prefix:        append([]byte(nil), test.prefix...),
				err:           transportErr,
			}
			_, err := mustOCIRemote(t, failing).ListAnnouncements(
				context.Background(), "", 10, newVerificationBudget(),
			)
			if !errors.Is(err, transportErr) {
				t.Fatalf("ListAnnouncements() error = %v, want operational body error", err)
			}
			if errors.Is(err, ErrInvalidRemoteObject) || errors.Is(err, errInvalidOCIManifest) {
				t.Fatalf("operational body error was downgraded to hostile: %v", err)
			}
		})
	}
}

func TestOCIBootstrapManifestValidationRejectsEnvelopeVariants(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	announcementBytes, err := EncodeCommitAnnouncement(fixture.announcement)
	if err != nil {
		t.Fatal(err)
	}
	announcement := descriptorFor(artifact.MediaTypeCommitAnnouncement, announcementBytes)
	valid, _, _, err := buildOCIAnnouncementBootstrapManifest(
		announcement, []artifact.Descriptor{fixture.grant, fixture.commit},
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*ocispec.Manifest){
		"artifact type": func(manifest *ocispec.Manifest) { manifest.ArtifactType = "application/example" },
		"config media":  func(manifest *ocispec.Manifest) { manifest.Config.MediaType = "application/json" },
		"annotations": func(manifest *ocispec.Manifest) {
			manifest.Annotations = map[string]string{"secret": "must-not-appear"}
		},
		"announcement not first": func(manifest *ocispec.Manifest) {
			manifest.Layers[0], manifest.Layers[1] = manifest.Layers[1], manifest.Layers[0]
		},
		"second announcement": func(manifest *ocispec.Manifest) {
			manifest.Layers = append(manifest.Layers, manifest.Layers[0])
		},
		"unsorted retained": func(manifest *ocispec.Manifest) {
			manifest.Layers[1], manifest.Layers[2] = manifest.Layers[2], manifest.Layers[1]
		},
		"descriptor metadata": func(manifest *ocispec.Manifest) {
			manifest.Layers[0].Annotations = map[string]string{"name": "secret"}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manifest := cloneOCIManifest(t, valid)
			mutate(&manifest)
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := decodeAndValidateOCIAnnouncementBootstrapManifest(encoded); !errors.Is(err, errInvalidOCIManifest) {
				t.Fatalf("validation error = %v, want errInvalidOCIManifest", err)
			}
		})
	}

	validBytes, _ := json.Marshal(valid)
	withUnknown := append([]byte(nil), validBytes[:len(validBytes)-1]...)
	withUnknown = append(withUnknown, []byte(`,"unknown":true}`)...)
	if _, _, _, err := decodeAndValidateOCIAnnouncementBootstrapManifest(withUnknown); !errors.Is(err, errInvalidOCIManifest) {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestOCIRemoteFailureOrderingNeverTags(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	target.failPushMedia(ocispec.MediaTypeImageManifest, errors.New("manifest upload failed"))
	remote := mustOCIRemote(t, target)
	if _, err := Publish(context.Background(), remote, fixture.local, publicationClosure(fixture.dependency), fixture.announcement); err == nil {
		t.Fatal("Publish() succeeded despite manifest upload failure")
	}
	if target.tagCount() != 0 {
		t.Fatal("tag was applied before manifest publication succeeded")
	}
	if eventIndex(target.snapshotEvents(), "push:"+OCIAnnouncementConfigMediaType) < 0 {
		t.Fatal("test did not reach config-before-manifest stage")
	}
}

func TestOCIRemoteMissingRetainedObjectNeverPublishesManifest(t *testing.T) {
	t.Parallel()
	fixture := newRegistryFixture(t)
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)
	encoded, _ := EncodeCommitAnnouncement(fixture.announcement)
	announcement := descriptorFor(artifact.MediaTypeCommitAnnouncement, encoded)
	if err := remote.Push(context.Background(), announcement, bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range []artifact.Descriptor{fixture.grant, fixture.commit} {
		copyRegistryTestObject(t, context.Background(), remote, fixture.local, descriptor)
	}
	tag, _ := AnnouncementTag(announcement.Digest)
	missing := descriptorFor(artifact.MediaTypeEncryptedChunk, []byte("missing"))
	retained := []artifact.Descriptor{fixture.grant, fixture.commit, missing}
	if err := remote.PublishAnnouncement(context.Background(), tag, announcement, retained); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("PublishAnnouncement() error = %v, want ErrObjectNotFound", err)
	}
	if target.eventCount("push:"+ocispec.MediaTypeImageManifest) != 0 || target.hasTag(tag) {
		t.Fatal("manifest or tag published before retained object existed")
	}
}

func TestOCIRemoteMissingOrMalformedPublicationMetadataNeverTags(t *testing.T) {
	t.Parallel()
	for _, fault := range []postIndexFault{
		postIndexMissingShard,
		postIndexMalformedShard,
		postIndexMissingIndex,
		postIndexMalformedIndex,
	} {
		fault := fault
		t.Run(fault.String(), func(t *testing.T) {
			t.Parallel()
			fixture := newRegistryFixture(t)
			base := newTestOCITarget()
			target := &postIndexFaultTarget{testOCITarget: base, fault: fault}
			remote := mustOCIRemote(t, target)

			announcement, err := Publish(
				context.Background(),
				remote,
				fixture.local,
				publicationClosure(fixture.dependency),
				fixture.announcement,
			)
			if err == nil {
				t.Fatal("Publish() succeeded after publication metadata fault")
			}
			tag, tagErr := AnnouncementTag(announcement.Digest)
			if tagErr == nil && base.hasTag(tag) {
				t.Fatal("faulted publication became visible")
			}
			if base.tagCount() != 0 {
				t.Fatalf("faulted publication installed %d tags", base.tagCount())
			}
		})
	}
}

func TestOCIRemoteInterruptedChildOrIndexUploadNeverTags(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		mediaType string
		ordinal   int
	}{
		{name: "retention shard", mediaType: ocispec.MediaTypeImageManifest, ordinal: 2},
		{name: "announcement index", mediaType: ocispec.MediaTypeImageIndex, ordinal: 1},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRegistryFixture(t)
			base := newTestOCITarget()
			target := &interruptingPushOCITarget{
				testOCITarget: base,
				mediaType:     test.mediaType,
				ordinal:       test.ordinal,
				err:           errors.New("publication interrupted"),
			}
			remote := mustOCIRemote(t, target)

			if _, err := Publish(
				context.Background(),
				remote,
				fixture.local,
				publicationClosure(fixture.dependency),
				fixture.announcement,
			); err == nil {
				t.Fatal("Publish() succeeded after interrupted metadata upload")
			}
			if base.tagCount() != 0 {
				t.Fatalf("interrupted publication installed %d tags", base.tagCount())
			}
		})
	}
}

func copyRegistryTestObject(
	t *testing.T,
	ctx context.Context,
	destination ObjectRemote,
	source artifact.ObjectSource,
	descriptor artifact.Descriptor,
) {
	t.Helper()
	stream, actual, err := source.Open(ctx, descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	if actual != descriptor {
		t.Fatalf("source descriptor = %#v, want %#v", actual, descriptor)
	}
	if err := destination.Push(ctx, descriptor, stream); err != nil {
		t.Fatal(err)
	}
}

func TestOCIRemoteCancellation(t *testing.T) {
	t.Parallel()
	target := newTestOCITarget()
	remote := mustOCIRemote(t, target)
	data := []byte("cancel me")
	descriptor := descriptorFor(artifact.MediaTypeEncryptedChunk, data)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := remote.Push(ctx, descriptor, bytes.NewReader(data)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Push() error = %v, want context.Canceled", err)
	}
	if _, err := remote.ListAnnouncements(ctx, "", 10, newVerificationBudget()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListAnnouncements() error = %v, want context.Canceled", err)
	}

	if err := remote.Push(context.Background(), descriptor, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	readCtx, stop := context.WithCancel(context.Background())
	stream, _, err := remote.Open(readCtx, descriptor.Digest)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Read() error = %v, want context.Canceled", err)
	}
}

func TestOCIRetainedClosureAboveFlatLimitHasDeterministicRoot(t *testing.T) {
	fixture := newRegistryFixture(t)
	announcement := encodedAnnouncementDescriptor(t, fixture.announcement)
	// 10,001 non-bootstrap layers force two shards. A flat announcement
	// manifest could not represent this closure under the 10,000-layer bound.
	retained := append(
		[]artifact.Descriptor{fixture.grant, fixture.commit},
		retainedChunkDescriptors(10_001, "above-flat-limit")...,
	)
	forward := buildTestOCIRetentionRoot(t, announcement, fixture.announcement, retained)
	if len(forward.shards) != 2 || forward.shardLayers[0] != MaxOCIRetentionShardLayers || forward.shardLayers[1] != 1 {
		t.Fatalf("shards/layers = %d/%v, want 2/[10000 1]", len(forward.shards), forward.shardLayers)
	}

	reversed := append([]artifact.Descriptor(nil), retained...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	backward := buildTestOCIRetentionRoot(t, announcement, fixture.announcement, reversed)
	if !bareOCIDescriptorsEqual(forward.root, backward.root) || !bytes.Equal(forward.encodedRoot, backward.encodedRoot) {
		t.Fatalf("root changed with input order: %#v != %#v", forward.root, backward.root)
	}
}

func TestOCIRetainedClosureExactMaximumAndMaximumPlusOne(t *testing.T) {
	// Keep this unit-level: constructing the complete 100k-descriptor metadata
	// plan exercises the real shard bytes/root while avoiding 100k registry
	// object uploads in a boundary test.
	fixture := newRegistryFixture(t)
	announcement := encodedAnnouncementDescriptor(t, fixture.announcement)
	chunks := retainedChunkDescriptors(MaxPublicationObjects-2, "publication-maximum")
	retained := append([]artifact.Descriptor{fixture.grant, fixture.commit}, chunks...)
	maximum := buildTestOCIRetentionRoot(t, announcement, fixture.announcement, retained)
	if len(maximum.shards) != 10 || len(maximum.index.Manifests) != MaxOCIAnnouncementIndexManifests {
		t.Fatalf("maximum root children = %d shards / %d manifests", len(maximum.shards), len(maximum.index.Manifests))
	}
	for index, size := range maximum.shardBytes {
		if size <= 0 || size > MaxOCIAnnouncementManifestBytes {
			t.Fatalf("maximum shard %d size = %d", index, size)
		}
	}

	closure := PublicationClosure{PayloadChunks: append([]artifact.Descriptor(nil), chunks...)}
	ordered, err := canonicalPublicationClosure(closure, fixture.grant, fixture.commit)
	if err != nil || len(ordered)+1 != MaxPublicationObjects {
		t.Fatalf("canonicalPublicationClosure(max) = %d, %v", len(ordered)+1, err)
	}
	overLimit := artifact.Descriptor{
		MediaType: artifact.MediaTypeEncryptedChunk,
		Digest:    digest.FromString("publication-over-limit"),
		Size:      1,
	}
	closure.PayloadChunks = append(closure.PayloadChunks, overLimit)
	if _, err := canonicalPublicationClosure(closure, fixture.grant, fixture.commit); err == nil {
		t.Fatal("canonicalPublicationClosure(max+1) succeeded")
	}
	if _, err := canonicalOCIRetained(append(retained, overLimit), announcement); err == nil {
		t.Fatal("canonicalOCIRetained(max+1) succeeded")
	}
}

type testOCIRetentionRoot struct {
	root        ocispec.Descriptor
	encodedRoot []byte
	index       ocispec.Index
	shards      []ocispec.Descriptor
	shardLayers []int
	shardBytes  []int
}

func buildTestOCIRetentionRoot(
	t *testing.T,
	announcementDescriptor artifact.Descriptor,
	announcement CommitAnnouncement,
	retained []artifact.Descriptor,
) testOCIRetentionRoot {
	t.Helper()
	ordered, err := canonicalOCIRetained(retained, announcementDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapRetained, shardRetained, err := partitionOCIRetained(ordered, announcement)
	if err != nil {
		t.Fatal(err)
	}
	_, _, bootstrap, err := buildOCIAnnouncementBootstrapManifest(announcementDescriptor, bootstrapRetained)
	if err != nil {
		t.Fatal(err)
	}
	result := testOCIRetentionRoot{}
	for first := 0; first < len(shardRetained); first += MaxOCIRetentionShardLayers {
		last := min(first+MaxOCIRetentionShardLayers, len(shardRetained))
		_, encoded, shard, err := buildOCIRetentionShardManifest(shardRetained[first:last])
		if err != nil {
			t.Fatal(err)
		}
		result.shards = append(result.shards, shard)
		result.shardLayers = append(result.shardLayers, last-first)
		result.shardBytes = append(result.shardBytes, len(encoded))
	}
	result.index, result.encodedRoot, result.root, err = buildOCIAnnouncementIndex(bootstrap, result.shards)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func encodedAnnouncementDescriptor(t *testing.T, announcement CommitAnnouncement) artifact.Descriptor {
	t.Helper()
	encoded, err := EncodeCommitAnnouncement(announcement)
	if err != nil {
		t.Fatal(err)
	}
	return descriptorFor(artifact.MediaTypeCommitAnnouncement, encoded)
}

func retainedChunkDescriptors(count int, namespace string) []artifact.Descriptor {
	result := make([]artifact.Descriptor, count)
	for index := range result {
		result[index] = artifact.Descriptor{
			MediaType: artifact.MediaTypeEncryptedChunk,
			Digest:    digest.FromString(fmt.Sprintf("%s-%d", namespace, index)),
			Size:      1,
		}
	}
	return result
}

func mustOCIRemote(t *testing.T, target OCITarget) *OCIRemote {
	t.Helper()
	remote, err := NewOCIRemote(target)
	if err != nil {
		t.Fatalf("NewOCIRemote() error = %v", err)
	}
	return remote
}

func publicationClosure(materials ...artifact.Descriptor) PublicationClosure {
	return PublicationClosure{MaterialManifests: materials}
}

func publishRawOCIAnnouncement(
	t *testing.T,
	target *testOCITarget,
	tag string,
	announcement artifact.Descriptor,
	retained []artifact.Descriptor,
) ocispec.Descriptor {
	t.Helper()
	ordered, err := canonicalOCIRetained(retained, announcement)
	if err != nil {
		t.Fatal(err)
	}
	announcementBytes := fetchTargetBytes(t, target, toOCIDescriptor(announcement))
	decoded, err := DecodeCommitAnnouncement(announcementBytes)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapRetained, shardRetained, err := partitionOCIRetained(ordered, decoded)
	if err != nil {
		t.Fatal(err)
	}
	_, bootstrapBytes, bootstrapDescriptor, err := buildOCIAnnouncementBootstrapManifest(announcement, bootstrapRetained)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Push(context.Background(), bootstrapDescriptor, bytes.NewReader(bootstrapBytes)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		t.Fatal(err)
	}
	shards := make([]ocispec.Descriptor, 0, retentionShardCount(len(shardRetained)))
	for first := 0; first < len(shardRetained); first += MaxOCIRetentionShardLayers {
		last := min(first+MaxOCIRetentionShardLayers, len(shardRetained))
		_, encoded, descriptor, err := buildOCIRetentionShardManifest(shardRetained[first:last])
		if err != nil {
			t.Fatal(err)
		}
		if err := target.Push(context.Background(), descriptor, bytes.NewReader(encoded)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
			t.Fatal(err)
		}
		shards = append(shards, descriptor)
	}
	_, encoded, descriptor, err := buildOCIAnnouncementIndex(bootstrapDescriptor, shards)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Push(context.Background(), descriptor, bytes.NewReader(encoded)); err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		t.Fatal(err)
	}
	target.setTag(tag, descriptor)
	return descriptor
}

func fetchTargetBytes(t *testing.T, target *testOCITarget, descriptor ocispec.Descriptor) []byte {
	t.Helper()
	reader, err := target.Fetch(context.Background(), descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneOCIManifest(t *testing.T, manifest ocispec.Manifest) ocispec.Manifest {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var clone ocispec.Manifest
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

type boundedOCIReader struct {
	source  io.Reader
	maximum int
}

func (r *boundedOCIReader) Read(destination []byte) (int, error) {
	if len(destination) > r.maximum {
		return 0, errors.New("OCI adapter requested an oversized source buffer")
	}
	return r.source.Read(destination)
}

type testOCITarget struct {
	store *memory.Store

	mu             sync.Mutex
	tags           map[string]ocispec.Descriptor
	events         []string
	pushFailures   map[string]error
	listErr        error
	afterTag       func(string)
	additionalTags []string
}

type scriptedTagsOCITarget struct {
	*testOCITarget
	pages [][]string
}

func (t *scriptedTagsOCITarget) Tags(ctx context.Context, _ string, callback func([]string) error) error {
	for _, page := range t.pages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := callback(append([]string(nil), page...)); err != nil {
			return err
		}
	}
	return nil
}

type bodyFailingOCITarget struct {
	*testOCITarget
	digest digest.Digest
	prefix []byte
	err    error
}

func (t *bodyFailingOCITarget) Fetch(ctx context.Context, descriptor ocispec.Descriptor) (io.ReadCloser, error) {
	if descriptor.Digest != t.digest {
		return t.testOCITarget.Fetch(ctx, descriptor)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return io.NopCloser(io.MultiReader(bytes.NewReader(t.prefix), terminalErrorReader{err: t.err})), nil
}

type terminalErrorReader struct {
	err error
}

func (r terminalErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type postIndexFault uint8

const (
	postIndexMissingShard postIndexFault = iota + 1
	postIndexMalformedShard
	postIndexMissingIndex
	postIndexMalformedIndex
)

func (f postIndexFault) String() string {
	switch f {
	case postIndexMissingShard:
		return "missing shard"
	case postIndexMalformedShard:
		return "malformed shard"
	case postIndexMissingIndex:
		return "missing index"
	case postIndexMalformedIndex:
		return "malformed index"
	default:
		return "unknown"
	}
}

// postIndexFaultTarget starts faulting only after the root index upload has
// completed. That proves PublishAnnouncement re-reads the complete metadata
// closure immediately before installing its tag instead of trusting earlier
// child upload acknowledgements.
type postIndexFaultTarget struct {
	*testOCITarget

	mu     sync.Mutex
	fault  postIndexFault
	active bool
	index  ocispec.Descriptor
	shard  ocispec.Descriptor
}

func (t *postIndexFaultTarget) Push(ctx context.Context, descriptor ocispec.Descriptor, source io.Reader) error {
	if descriptor.MediaType != ocispec.MediaTypeImageIndex {
		return t.testOCITarget.Push(ctx, descriptor, source)
	}
	encoded, err := io.ReadAll(source)
	if err != nil {
		return err
	}
	if err := t.testOCITarget.Push(ctx, descriptor, bytes.NewReader(encoded)); err != nil {
		return err
	}
	var index ocispec.Index
	if err := json.Unmarshal(encoded, &index); err != nil {
		return err
	}
	if len(index.Manifests) < 2 {
		return errors.New("test publication has no retention shard")
	}
	t.mu.Lock()
	t.active = true
	t.index = descriptor
	t.shard = index.Manifests[1]
	t.mu.Unlock()
	return nil
}

func (t *postIndexFaultTarget) Fetch(ctx context.Context, descriptor ocispec.Descriptor) (io.ReadCloser, error) {
	t.mu.Lock()
	active := t.active
	fault := t.fault
	index := t.index
	shard := t.shard
	t.mu.Unlock()

	targeted := (fault == postIndexMissingShard || fault == postIndexMalformedShard) &&
		bareOCIDescriptorsEqual(descriptor, shard) ||
		(fault == postIndexMissingIndex || fault == postIndexMalformedIndex) &&
			bareOCIDescriptorsEqual(descriptor, index)
	if !active || !targeted {
		return t.testOCITarget.Fetch(ctx, descriptor)
	}
	if fault == postIndexMissingShard || fault == postIndexMissingIndex {
		return nil, errdef.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{0xff}, int(descriptor.Size)))), nil
}

type interruptingPushOCITarget struct {
	*testOCITarget

	mu        sync.Mutex
	mediaType string
	ordinal   int
	observed  int
	err       error
}

func (t *interruptingPushOCITarget) Push(ctx context.Context, descriptor ocispec.Descriptor, source io.Reader) error {
	if descriptor.MediaType == t.mediaType {
		t.mu.Lock()
		t.observed++
		interrupt := t.observed == t.ordinal
		t.mu.Unlock()
		if interrupt {
			return t.err
		}
	}
	return t.testOCITarget.Push(ctx, descriptor, source)
}

func newTestOCITarget() *testOCITarget {
	return &testOCITarget{
		store:        memory.New(),
		tags:         make(map[string]ocispec.Descriptor),
		pushFailures: make(map[string]error),
	}
}

func (t *testOCITarget) Fetch(ctx context.Context, descriptor ocispec.Descriptor) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return t.store.Fetch(ctx, descriptor)
}

func (t *testOCITarget) Push(ctx context.Context, descriptor ocispec.Descriptor, source io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	t.events = append(t.events, "push:"+descriptor.MediaType)
	failure := t.pushFailures[descriptor.MediaType]
	t.mu.Unlock()
	if failure != nil {
		return failure
	}
	return t.store.Push(ctx, descriptor, source)
}

func (t *testOCITarget) Exists(ctx context.Context, descriptor ocispec.Descriptor) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return t.store.Exists(ctx, descriptor)
}

func (t *testOCITarget) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return ocispec.Descriptor{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	descriptor, ok := t.tags[reference]
	if !ok {
		return ocispec.Descriptor{}, errdef.ErrNotFound
	}
	return descriptor, nil
}

func (t *testOCITarget) Tag(ctx context.Context, descriptor ocispec.Descriptor, reference string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	exists, err := t.store.Exists(ctx, descriptor)
	if err != nil {
		return err
	}
	if !exists {
		return errdef.ErrNotFound
	}
	t.mu.Lock()
	t.tags[reference] = descriptor
	t.events = append(t.events, "tag:"+reference)
	hook := t.afterTag
	t.mu.Unlock()
	if hook != nil {
		hook(reference)
	}
	return nil
}

func (t *testOCITarget) Tags(ctx context.Context, last string, callback func([]string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.mu.Lock()
	if t.listErr != nil {
		err := t.listErr
		t.mu.Unlock()
		return err
	}
	tags := make([]string, 0, len(t.tags)+len(t.additionalTags))
	for tag := range t.tags {
		tags = append(tags, tag)
	}
	tags = append(tags, t.additionalTags...)
	t.mu.Unlock()
	sort.Strings(tags)
	start := sort.SearchStrings(tags, last)
	for start < len(tags) && tags[start] <= last {
		start++
	}
	return callback(tags[start:])
}

func (t *testOCITarget) setTag(tag string, descriptor ocispec.Descriptor) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tags[tag] = descriptor
}

func (t *testOCITarget) deleteTag(tag string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.tags, tag)
}

func (t *testOCITarget) hasTag(tag string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.tags[tag]
	return ok
}

func (t *testOCITarget) tagCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.tags)
}

func (t *testOCITarget) setAfterTag(hook func(string)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.afterTag = hook
}

func (t *testOCITarget) failPushMedia(mediaType string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pushFailures[mediaType] = err
}

func (t *testOCITarget) snapshotEvents() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.events...)
}

func (t *testOCITarget) eventCount(event string) int {
	count := 0
	for _, candidate := range t.snapshotEvents() {
		if candidate == event {
			count++
		}
	}
	return count
}

func announcementRefTags(refs []AnnouncementRef) []string {
	tags := make([]string, len(refs))
	for index, ref := range refs {
		tags[index] = ref.Tag
	}
	return tags
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestOCIRemoteIgnoresNonAnnouncementTags(t *testing.T) {
	t.Parallel()
	target := newTestOCITarget()
	target.additionalTags = []string{"latest", "head", "commit-malformed"}
	remote := mustOCIRemote(t, target)
	page, err := remote.ListAnnouncements(context.Background(), "", 10, newVerificationBudget())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Refs) != 1 || !strings.HasPrefix(page.Refs[0].Tag, announcementTagPrefix) {
		t.Fatalf("page = %#v", page)
	}
}

package registry_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/policy"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/errdef"
)

func TestFreshOCIRemoteDiscoversAndOpensRetainedGraph(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	objects := newFreshClientObjects()
	target := newFreshClientOCITarget()
	publisherRemote, err := registry.NewOCIRemote(target)
	if err != nil {
		t.Fatal(err)
	}

	device, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	assertion := []byte("fresh-client-enrollment")
	claims := artifact.EnrollmentClaims{
		DeviceID:         device.DeviceID(),
		Subject:          "github:user:1001",
		X25519Recipient:  device.RecipientString(),
		Ed25519PublicKey: device.SigningPublicKey(),
	}
	verifier := freshClientEnrollmentVerifier(func(_ context.Context, candidate []byte) (artifact.EnrollmentClaims, error) {
		if !bytes.Equal(candidate, assertion) {
			return artifact.EnrollmentClaims{}, errors.New("unknown enrollment")
		}
		return claims, nil
	})
	verified, err := artifact.VerifyEnrollment(ctx, verifier, assertion)
	if err != nil {
		t.Fatal(err)
	}
	sealer := engine.Sealer{Sink: objects, Issuer: device, Recipients: []artifact.VerifiedDevice{verified}}

	policySchema := mustFreshClientTypeRef(t, "schemas.enbu.net/v1alpha1/RegoPolicy")
	sealedPolicy, err := sealer.SealPolicyDraft(ctx, engine.Draft{
		Kind: artifact.KindResource, UID: mustFreshClientUUID(t, "11111111-1111-4111-8111-111111111111"), Schema: policySchema,
		Metadata: artifact.Metadata{Name: "owner-policy"},
		Payloads: []engine.PayloadSource{{Name: "policy.rego", MediaType: "text/plain", Reader: bytes.NewReader(policy.OwnerOnlyPolicy())}},
	})
	if err != nil {
		t.Fatal(err)
	}
	secretSchema := mustFreshClientTypeRef(t, "schemas.enbu.net/v1alpha1/Opaque")
	sealedSecret, err := sealer.SealDraft(ctx, engine.Draft{
		Kind: artifact.KindResource, UID: mustFreshClientUUID(t, "22222222-2222-4222-8222-222222222222"), Schema: secretSchema,
		Metadata: artifact.Metadata{Name: "ssh-private-key"},
		Payloads: []engine.PayloadSource{{Name: "key", MediaType: "application/x-pem-file", Reader: bytes.NewReader([]byte("secret-key"))}},
	}, sealedPolicy.Ref.Revision)
	if err != nil {
		t.Fatal(err)
	}
	rootSchema := mustFreshClientTypeRef(t, "schemas.enbu.net/v1alpha1/ValueTree")
	sealedRoot, err := sealer.SealDraft(ctx, engine.Draft{
		Kind: artifact.KindCollection, UID: mustFreshClientUUID(t, "33333333-3333-4333-8333-333333333333"), Schema: rootSchema,
		Metadata: artifact.Metadata{Name: "workspace"},
		Edges: []artifact.Edge{{
			ID: mustFreshClientUUID(t, "44444444-4444-4444-8444-444444444444"), Name: "ssh-key",
			Relation: artifact.MemberRelation(), Strength: artifact.EdgePinned,
			Target: sealedSecret.Revision.UID, Pinned: &sealedSecret.Ref,
		}},
	}, sealedPolicy.Ref.Revision)
	if err != nil {
		t.Fatal(err)
	}

	workspaceID := mustFreshClientUUID(t, "55555555-5555-4555-8555-555555555555")
	publisher := engine.Publisher{
		Local: objects, Remote: publisherRemote, Device: device, Author: verified,
		Recipients: []artifact.VerifiedDevice{verified}, Audit: freshClientAudit{},
		Now: func() time.Time { return time.Date(2026, 8, 9, 2, 3, 4, 5, time.UTC) },
	}
	published, err := publisher.Publish(ctx, engine.AuditActionInitialize, engine.CommitMutation{
		WorkspaceID: workspaceID, Root: sealedRoot.Ref, Policy: sealedPolicy.Ref,
		Actor: verified.Subject(), OperationID: mustFreshClientUUID(t, "66666666-6666-4666-8666-666666666666"),
		Provenance: []commitmodel.MutationProvenance{{
			ID: mustFreshClientUUID(t, "77777777-7777-4777-8777-777777777777"), Action: commitmodel.InitializeAction(),
			Target: sealedRoot.Revision.UID, After: &sealedRoot.Ref,
		}},
		Closure: engine.MergeClosures(sealedRoot.Closure, sealedSecret.Closure, sealedPolicy.Closure),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A new adapter has no Push-derived descriptor cache and shares only the
	// registry's immutable content and tags with the publisher.
	freshRemote, err := registry.NewOCIRemote(target)
	if err != nil {
		t.Fatal(err)
	}
	commitVerifier, err := registry.NewEncryptedCommitVerifier(freshRemote, device, verifier)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := registry.Discover(ctx, workspaceID, freshRemote, commitVerifier)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discovery.Announcements) != 1 || discovery.Announcements[0].Commit.CommitID != published.CommitID {
		t.Fatalf("Discovery = %#v", discovery)
	}
	dag, err := discovery.BuildDAG(ctx)
	if err != nil {
		t.Fatal(err)
	}
	frontier := dag.Frontier()
	if len(frontier) != 1 || frontier[0] != published.CommitID {
		t.Fatalf("frontier = %v", frontier)
	}
	graph, err := engine.OpenGraph(ctx, freshRemote, device, verifier, discovery.Announcements[0].Commit.Value.Commit().Root)
	if err != nil {
		t.Fatalf("OpenGraph() from fresh OCI adapter error = %v", err)
	}
	if len(graph.ByUID) != 2 || graph.ByUID[sealedSecret.Revision.UID].Ref != sealedSecret.Ref {
		t.Fatalf("fresh graph = %#v", graph)
	}
}

type freshClientEnrollmentVerifier func(context.Context, []byte) (artifact.EnrollmentClaims, error)

func (verify freshClientEnrollmentVerifier) VerifyEnrollment(ctx context.Context, assertion []byte) (artifact.EnrollmentClaims, error) {
	return verify(ctx, assertion)
}

type freshClientAudit struct{}

func (freshClientAudit) Started(context.Context, artifact.UUID, engine.AuditAction, digest.Digest) error {
	return nil
}

func (freshClientAudit) Finished(context.Context, artifact.UUID, engine.AuditAction, digest.Digest, engine.AuditResult) error {
	return nil
}

type freshClientStoredObject struct {
	descriptor artifact.Descriptor
	data       []byte
}

type freshClientObjects struct {
	mu      sync.Mutex
	objects map[digest.Digest]freshClientStoredObject
}

func newFreshClientObjects() *freshClientObjects {
	return &freshClientObjects{objects: make(map[digest.Digest]freshClientStoredObject)}
}

func (store *freshClientObjects) Ingest(ctx context.Context, mediaType string, source io.Reader) (artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return artifact.Descriptor{}, err
	}
	data, err := io.ReadAll(source)
	if err != nil {
		return artifact.Descriptor{}, err
	}
	descriptor := artifact.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
	if err := descriptor.Validate(); err != nil {
		return artifact.Descriptor{}, err
	}
	store.mu.Lock()
	store.objects[descriptor.Digest] = freshClientStoredObject{descriptor: descriptor, data: append([]byte(nil), data...)}
	store.mu.Unlock()
	return descriptor, nil
}

func (store *freshClientObjects) Open(ctx context.Context, value digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	store.mu.Lock()
	object, ok := store.objects[value]
	store.mu.Unlock()
	if !ok {
		return nil, artifact.Descriptor{}, errors.New("object not found")
	}
	return io.NopCloser(bytes.NewReader(object.data)), object.descriptor, nil
}

type freshClientOCITarget struct {
	*memory.Store

	mu   sync.Mutex
	tags map[string]ocispec.Descriptor
}

func newFreshClientOCITarget() *freshClientOCITarget {
	return &freshClientOCITarget{Store: memory.New(), tags: make(map[string]ocispec.Descriptor)}
}

func (target *freshClientOCITarget) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return ocispec.Descriptor{}, err
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	descriptor, ok := target.tags[reference]
	if !ok {
		return ocispec.Descriptor{}, errdef.ErrNotFound
	}
	return descriptor, nil
}

func (target *freshClientOCITarget) Tag(ctx context.Context, descriptor ocispec.Descriptor, reference string) error {
	exists, err := target.Exists(ctx, descriptor)
	if err != nil {
		return err
	}
	if !exists {
		return errdef.ErrNotFound
	}
	target.mu.Lock()
	target.tags[reference] = descriptor
	target.mu.Unlock()
	return nil
}

func (target *freshClientOCITarget) Tags(ctx context.Context, last string, callback func([]string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target.mu.Lock()
	tags := make([]string, 0, len(target.tags))
	for tag := range target.tags {
		tags = append(tags, tag)
	}
	target.mu.Unlock()
	sort.Strings(tags)
	first := sort.Search(len(tags), func(index int) bool { return tags[index] > last })
	return callback(tags[first:])
}

func mustFreshClientUUID(t *testing.T, value string) artifact.UUID {
	t.Helper()
	parsed, err := artifact.ParseUUID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func mustFreshClientTypeRef(t *testing.T, value string) artifact.TypeRef {
	t.Helper()
	parsed, err := artifact.ParseTypeRef(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

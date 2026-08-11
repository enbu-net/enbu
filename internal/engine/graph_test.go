package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/opencontainers/go-digest"
)

func TestOpenGraphAuthenticatesExactPinnedClosure(t *testing.T) {
	t.Parallel()

	objects := newMemoryObjects()
	device, verified, verifier := testDevice(t)
	sealer := Sealer{Sink: objects, Issuer: device, Recipients: []artifact.VerifiedDevice{verified}}
	schema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	policy := digest.FromString("policy")
	child, err := sealer.SealDraft(context.Background(), Draft{
		Kind: artifact.KindResource, UID: testUUID(t, "55555555-5555-4555-8555-555555555555"), Schema: schema,
		Metadata: artifact.Metadata{Name: "ssh-private-key"},
		Payloads: []PayloadSource{{Name: "key", MediaType: "application/x-pem-file", Reader: strings.NewReader("private-key")}},
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	rootSchema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/ValueTree")
	root, err := sealer.SealDraft(context.Background(), Draft{
		Kind: artifact.KindCollection, UID: testUUID(t, "66666666-6666-4666-8666-666666666666"), Schema: rootSchema,
		Metadata: artifact.Metadata{Name: "workspace"},
		Edges: []artifact.Edge{{
			ID: testUUID(t, "77777777-7777-4777-8777-777777777777"), Name: "ssh-key",
			Relation: artifact.MemberRelation(), Strength: artifact.EdgePinned,
			Target: child.Revision.UID, Pinned: &child.Ref,
		}},
	}, policy)
	if err != nil {
		t.Fatal(err)
	}

	graph, err := OpenGraph(context.Background(), objects, device, verifier, root.Ref)
	if err != nil {
		t.Fatalf("OpenGraph: %v", err)
	}
	if len(graph.ByUID) != 2 || graph.ByUID[child.Revision.UID].Ref != child.Ref {
		t.Fatalf("Graph = %#v", graph)
	}
}

func TestOpenGraphRejectsSameUIDAtTwoPinnedRevisions(t *testing.T) {
	t.Parallel()

	objects := newMemoryObjects()
	device, verified, verifier := testDevice(t)
	sealer := Sealer{Sink: objects, Issuer: device, Recipients: []artifact.VerifiedDevice{verified}}
	schema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	policy := digest.FromString("policy")
	uid := testUUID(t, "88888888-8888-4888-8888-888888888888")
	first, err := sealer.SealDraft(context.Background(), Draft{Kind: artifact.KindResource, UID: uid, Schema: schema, Metadata: artifact.Metadata{Name: "first"}, Payloads: []PayloadSource{{Name: "data", MediaType: "application/octet-stream", Reader: strings.NewReader("one")}}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealer.SealDraft(context.Background(), Draft{Kind: artifact.KindResource, UID: uid, Schema: schema, Metadata: artifact.Metadata{Name: "second"}, Payloads: []PayloadSource{{Name: "data", MediaType: "application/octet-stream", Reader: strings.NewReader("two")}}}, policy)
	if err != nil {
		t.Fatal(err)
	}
	rootSchema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/ValueTree")
	root, err := sealer.SealDraft(context.Background(), Draft{
		Kind: artifact.KindCollection, UID: testUUID(t, "99999999-9999-4999-8999-999999999999"), Schema: rootSchema,
		Metadata: artifact.Metadata{Name: "ambiguous"},
		Edges: []artifact.Edge{
			{ID: testUUID(t, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), Name: "first", Relation: artifact.MemberRelation(), Strength: artifact.EdgePinned, Target: uid, Pinned: &first.Ref},
			{ID: testUUID(t, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), Name: "second", Relation: artifact.MemberRelation(), Strength: artifact.EdgePinned, Target: uid, Pinned: &second.Ref},
		},
	}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenGraph(context.Background(), objects, device, verifier, root.Ref); !errors.Is(err, artifact.ErrConflictingUID) {
		t.Fatalf("OpenGraph ambiguity = %v", err)
	}
}

func TestEnqueuePinnedDeduplicatesFrontierAndRejectsConflictingRef(t *testing.T) {
	t.Parallel()

	revision := digest.FromString("queued revision")
	ref := artifact.SealedRef{
		Revision: revision,
		Material: digest.FromString("material"),
		Grant:    digest.FromString("grant"),
	}
	pending := make([]artifact.SealedRef, 0, 1)
	queued := make(map[digest.Digest]artifact.SealedRef)
	opened := make(map[digest.Digest]OpenedRevision)
	for range 50_000 {
		if err := enqueuePinned(&pending, queued, opened, ref); err != nil {
			t.Fatalf("enqueue duplicate: %v", err)
		}
	}
	if len(pending) != 1 || len(queued) != 1 {
		t.Fatalf("frontier = %d pending, %d queued", len(pending), len(queued))
	}

	conflicting := ref
	conflicting.Grant = digest.FromString("other grant")
	if err := enqueuePinned(&pending, queued, opened, conflicting); !errors.Is(err, artifact.ErrPinnedTargetMismatch) {
		t.Fatalf("conflicting queued ref = %v", err)
	}
}

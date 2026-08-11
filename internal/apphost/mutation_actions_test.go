package apphost

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/cas"
	"github.com/enbu-net/enbu/pkg/enrollment"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/schema"
	"github.com/opencontainers/go-digest"
)

func TestMergeSecretValuesMergesDistinctKeysAndRejectsSameKeyConflict(t *testing.T) {
	t.Parallel()

	base := schema.SecretMap{"A": "base", "UNCHANGED": "same"}
	merged, err := mergeSecretValues(base, []schema.SecretMap{
		{"A": "left", "UNCHANGED": "same"},
		{"A": "base", "B": "right", "UNCHANGED": "same"},
	})
	if err != nil {
		t.Fatalf("merge distinct keys: %v", err)
	}
	if merged["A"] != "left" || merged["B"] != "right" || merged["UNCHANGED"] != "same" {
		t.Fatalf("merged = %#v", merged)
	}
	if _, err := mergeSecretValues(base, []schema.SecretMap{{"A": "left"}, {"A": "right"}}); !errors.Is(err, errSemanticMergeConflict) {
		t.Fatalf("same-key conflict = %v, want %v", err, errSemanticMergeConflict)
	}
}

func TestMergeEdgesUsesStableEdgeIdentityAndIgnoresPinnedRefPropagation(t *testing.T) {
	t.Parallel()

	parent := mustActionUUID(t, "10000000-0000-4000-8000-000000000001")
	leftID := mustActionUUID(t, "10000000-0000-4000-8000-000000000002")
	rightID := mustActionUUID(t, "10000000-0000-4000-8000-000000000003")
	base := testPinnedEdge(t, parent, "base", mustActionUUID(t, "10000000-0000-4000-8000-000000000004"), "base")
	propagated := cloneEdge(base)
	propagated.Pinned = testSealedRef("propagated")
	left := testPinnedEdge(t, leftID, "left", mustActionUUID(t, "10000000-0000-4000-8000-000000000005"), "left")
	right := testPinnedEdge(t, rightID, "right", mustActionUUID(t, "10000000-0000-4000-8000-000000000006"), "right")

	merged, err := mergeEdges([]artifact.Edge{base}, [][]artifact.Edge{{propagated, left}, {base, right}})
	if err != nil {
		t.Fatalf("merge distinct edge IDs: %v", err)
	}
	if len(merged) != 3 {
		t.Fatalf("merged edges = %#v", merged)
	}
	leftChanged := cloneEdge(base)
	leftChanged.Name = "left-name"
	rightChanged := cloneEdge(base)
	rightChanged.Name = "right-name"
	if _, err := mergeEdges([]artifact.Edge{base}, [][]artifact.Edge{{leftChanged}, {rightChanged}}); !errors.Is(err, errSemanticMergeConflict) {
		t.Fatalf("same-edge conflict = %v, want %v", err, errSemanticMergeConflict)
	}
}

func TestDeterministicMergeConflictIDBindsConflictShape(t *testing.T) {
	t.Parallel()

	target := mustActionUUID(t, "20000000-0000-4000-8000-000000000001")
	base := digest.FromString("base")
	heads := []digest.Digest{digest.FromString("left"), digest.FromString("right")}
	first := deterministicConflictID(host.ConflictAccess, target, base, heads, "access")
	second := deterministicConflictID(host.ConflictAccess, target, base, heads, "access")
	if first != second || first == deterministicConflictID(host.ConflictPolicy, target, base, heads, "access") {
		t.Fatalf("conflict IDs are not stable/domain-bound: %s %s", first, second)
	}
}

func TestExpandGrantTargetsIncludesOnlyStrongAncestors(t *testing.T) {
	t.Parallel()

	root := artifact.UUID("11111111-1111-4111-8111-111111111111")
	parent := artifact.UUID("22222222-2222-4222-8222-222222222222")
	target := artifact.UUID("33333333-3333-4333-8333-333333333333")
	sibling := artifact.UUID("44444444-4444-4444-8444-444444444444")
	rootRef := *testSealedRef("grant-root")
	graph := engine.Graph{
		Root: rootRef,
		ByRevision: map[digest.Digest]engine.OpenedRevision{
			rootRef.Revision: {Ref: rootRef, Revision: artifact.Revision{UID: root}},
		},
		ByUID: map[artifact.UUID]engine.OpenedRevision{
			root: {Ref: rootRef, Revision: artifact.Revision{UID: root, Edges: []artifact.Edge{
				{Strength: artifact.EdgePinned, Target: parent},
				{Strength: artifact.EdgePinned, Target: sibling},
			}}},
			parent:  {Revision: artifact.Revision{UID: parent, Edges: []artifact.Edge{{Strength: artifact.EdgePinned, Target: target}}}},
			target:  {Revision: artifact.Revision{UID: target}},
			sibling: {Revision: artifact.Revision{UID: sibling}},
		},
	}
	expanded, err := expandGrantTargets(graph, []artifact.UUID{target})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[artifact.UUID]struct{}, len(expanded))
	for _, uid := range expanded {
		got[uid] = struct{}{}
	}
	for _, uid := range []artifact.UUID{root, parent, target} {
		if _, exists := got[uid]; !exists {
			t.Fatalf("missing ancestor %s in %#v", uid, expanded)
		}
	}
	if _, exists := got[sibling]; exists {
		t.Fatalf("sibling was granted: %#v", expanded)
	}
}

func TestMergeChangesRecipientSetsDetectsAccessMutation(t *testing.T) {
	t.Parallel()

	uid := artifact.UUID("55555555-5555-4555-8555-555555555555")
	base := engine.Graph{ByUID: map[artifact.UUID]engine.OpenedRevision{
		uid: {Revision: artifact.Revision{UID: uid}, Grant: artifact.OpenedGrant{Claims: artifact.GrantClaims{
			Recipients: []artifact.GrantRecipient{{DeviceID: artifact.UUID("66666666-6666-4666-8666-666666666666")}},
		}}},
	}}
	same := engine.Graph{ByUID: map[artifact.UUID]engine.OpenedRevision{
		uid: base.ByUID[uid],
	}}
	if mergeChangesRecipientSets(base, []engine.Graph{same}) {
		t.Fatal("unchanged recipient set was reported as changed")
	}
	changedOpened := base.ByUID[uid]
	changedOpened.Grant.Claims.Recipients = append(changedOpened.Grant.Claims.Recipients, artifact.GrantRecipient{
		DeviceID: artifact.UUID("77777777-7777-4777-8777-777777777777"),
	})
	changed := engine.Graph{ByUID: map[artifact.UUID]engine.OpenedRevision{uid: changedOpened}}
	if !mergeChangesRecipientSets(base, []engine.Graph{changed}) {
		t.Fatal("recipient expansion was not detected")
	}
}

func TestGraphResealerGrantRewrapPreservesMaterialButRevokeRekeys(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name               string
		initialRecipients  int
		finalRecipients    int
		rewrap             bool
		forceSeal          bool
		wantMaterialChange bool
		secondCanOpen      bool
	}{
		{name: "grant-rewrap", initialRecipients: 1, finalRecipients: 2, rewrap: true, wantMaterialChange: false, secondCanOpen: true},
		{name: "revoke-rekey", initialRecipients: 2, finalRecipients: 1, forceSeal: true, wantMaterialChange: true, secondCanOpen: false},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResealFixture(t, test.initialRecipients)
			defer func() { _ = fixture.objects.Close() }()

			nodes := make(map[artifact.UUID]*revisionPlan, len(fixture.graph.ByUID))
			for uid, opened := range fixture.graph.ByUID {
				recipients, err := verifiedGrantRecipients(context.Background(), opened.Grant.Claims.Recipients, fixture.verifier)
				if err != nil {
					t.Fatal(err)
				}
				nodes[uid] = revisionPlanFromOpened(opened, recipients)
			}
			child := nodes[fixture.childUID]
			child.recipients = append([]artifact.VerifiedDevice(nil), fixture.devices[:test.finalRecipients]...)
			child.rewrapOnly = test.rewrap
			child.forceSeal = test.forceSeal
			builder := newGraphResealer(context.Background(), fixture.state, fixture.policy, nodes)
			newRoot, err := builder.seal(fixture.rootUID)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			materialChanged := child.result.Material != fixture.child.Ref.Material
			if materialChanged != test.wantMaterialChange || child.result.Grant == fixture.child.Ref.Grant || newRoot == fixture.graph.Root {
				t.Fatalf("result child=%#v old=%#v rootChanged=%v", child.result, fixture.child.Ref, newRoot != fixture.graph.Root)
			}
			_, secondErr := engine.OpenGraph(context.Background(), fixture.objects, fixture.identities[1], fixture.verifier, newRoot)
			if test.secondCanOpen && secondErr != nil {
				t.Fatalf("second device should open rewrapped graph: %v", secondErr)
			}
			if !test.secondCanOpen && !errors.Is(secondErr, artifact.ErrGrantAccessDenied) {
				t.Fatalf("second device open = %v, want access denied", secondErr)
			}
		})
	}
}

type resealFixture struct {
	objects    *cas.Store
	state      *workspaceState
	verifier   *enrollment.Verifier
	identities []*artifact.DeviceIdentity
	devices    []artifact.VerifiedDevice
	policy     artifact.SealedRef
	graph      engine.Graph
	rootUID    artifact.UUID
	childUID   artifact.UUID
	child      engine.OpenedRevision
}

func newResealFixture(t *testing.T, childRecipientCount int) resealFixture {
	t.Helper()
	ctx := context.Background()
	issuer, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	second, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := enrollment.NewAuthority("tests.enbu.net", issuer.SigningPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := enrollment.NewVerifier([]enrollment.Authority{authority})
	if err != nil {
		t.Fatal(err)
	}
	identities := []*artifact.DeviceIdentity{issuer, second}
	devices := make([]artifact.VerifiedDevice, 0, len(identities))
	for index, identity := range identities {
		assertion, err := enrollment.SignWithSigner(enrollment.Claims{
			Issuer: "tests.enbu.net", DeviceID: identity.DeviceID(), Subject: "github:test:" + string(rune('a'+index)),
			X25519Recipient: identity.RecipientString(), Ed25519PublicKey: identity.SigningPublicKey(),
		}, issuer)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := artifact.VerifyEnrollment(ctx, verifier, assertion)
		if err != nil {
			t.Fatal(err)
		}
		devices = append(devices, verified)
	}
	objects, err := cas.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policy := artifact.SealedRef{Revision: digest.FromString("policy-revision"), Material: digest.FromString("policy-material"), Grant: digest.FromString("policy-grant")}
	childUID := mustActionUUID(t, "30000000-0000-4000-8000-000000000001")
	rootUID := mustActionUUID(t, "30000000-0000-4000-8000-000000000002")
	opaque, _ := artifact.ParseTypeRef(schema.SchemaOpaque)
	workspaceType, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Workspace")
	child, err := (engine.Sealer{Sink: objects, Issuer: issuer, Recipients: devices[:childRecipientCount]}).SealDraft(ctx, engine.Draft{
		Kind: artifact.KindResource, UID: childUID, Schema: opaque, Metadata: artifact.Metadata{Name: "child"},
		Payloads: []engine.PayloadSource{{Name: "data", MediaType: "application/octet-stream", Reader: bytes.NewBufferString("secret")}},
	}, policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	edgeID := mustActionUUID(t, "30000000-0000-4000-8000-000000000003")
	childRef := child.Ref
	root, err := (engine.Sealer{Sink: objects, Issuer: issuer, Recipients: devices}).SealDraft(ctx, engine.Draft{
		Kind: artifact.KindCollection, UID: rootUID, Schema: workspaceType, Metadata: artifact.Metadata{Name: "root"},
		Edges: []artifact.Edge{{ID: edgeID, Name: "child", Relation: artifact.MemberRelation(), Strength: artifact.EdgePinned, Target: childUID, Pinned: &childRef}},
	}, policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := engine.OpenGraph(ctx, objects, issuer, verifier, root.Ref)
	if err != nil {
		t.Fatal(err)
	}
	state := &workspaceState{objects: objects, device: issuer, author: devices[0], verifier: verifier}
	return resealFixture{
		objects: objects, state: state, verifier: verifier, identities: identities, devices: devices,
		policy: policy, graph: graph, rootUID: rootUID, childUID: childUID, child: graph.ByUID[childUID],
	}
}

func testPinnedEdge(t *testing.T, id artifact.UUID, name string, target artifact.UUID, seed string) artifact.Edge {
	t.Helper()
	return artifact.Edge{
		ID: id, Name: name, Relation: artifact.MemberRelation(), Strength: artifact.EdgePinned,
		Target: target, Pinned: testSealedRef(seed),
	}
}

func testSealedRef(seed string) *artifact.SealedRef {
	value := artifact.SealedRef{
		Revision: digest.FromString(seed + "-revision"), Material: digest.FromString(seed + "-material"), Grant: digest.FromString(seed + "-grant"),
	}
	return &value
}

func mustActionUUID(t *testing.T, value string) artifact.UUID {
	t.Helper()
	parsed, err := artifact.ParseUUID(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

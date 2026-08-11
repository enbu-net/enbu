package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/policy"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/opencontainers/go-digest"
)

func TestPublisherCreatesDiscoverableAuditedInitialization(t *testing.T) {
	t.Parallel()

	local := newMemoryObjects()
	remote := newMemoryRemote()
	device, verified, verifier := testDevice(t)
	sealer := Sealer{Sink: local, Issuer: device, Recipients: []artifact.VerifiedDevice{verified}}
	policyType, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/RegoPolicy")
	sealedPolicy, err := sealer.SealPolicyDraft(context.Background(), Draft{
		Kind: artifact.KindResource, UID: testUUID(t, "10101010-1010-4010-8010-101010101010"), Schema: policyType,
		Metadata: artifact.Metadata{Name: "owner-policy"},
		Payloads: []PayloadSource{{Name: "policy.rego", MediaType: "text/plain", Reader: bytes.NewReader(policy.OwnerOnlyPolicy())}},
	})
	if err != nil {
		t.Fatalf("SealPolicyDraft: %v", err)
	}
	if openedPolicy, openErr := OpenRevision(context.Background(), local, device, verifier, sealedPolicy.Ref); openErr != nil || openedPolicy.Grant.Claims.Policy != sealedPolicy.Ref.Revision {
		t.Fatalf("self-bound policy = %#v, %v", openedPolicy, openErr)
	}
	rootType, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/ValueTree")
	sealedRoot, err := sealer.SealDraft(context.Background(), Draft{
		Kind: artifact.KindCollection, UID: testUUID(t, "20202020-2020-4020-8020-202020202020"), Schema: rootType,
		Metadata: artifact.Metadata{Name: "workspace-root"},
	}, sealedPolicy.Ref.Revision)
	if err != nil {
		t.Fatalf("SealDraft(root): %v", err)
	}
	workspaceID := testUUID(t, "30303030-3030-4030-8030-303030303030")
	operationID := testUUID(t, "40404040-4040-4040-8040-404040404040")
	provenanceID := testUUID(t, "50505050-5050-4050-8050-505050505050")
	audit := &recordingAudit{}
	publisher := Publisher{
		Local: local, Remote: remote, Device: device, Author: verified,
		Recipients: []artifact.VerifiedDevice{verified}, Audit: audit,
		Now: func() time.Time { return time.Date(2026, 8, 9, 1, 2, 3, 4, time.UTC) },
	}
	published, err := publisher.Publish(context.Background(), AuditActionInitialize, CommitMutation{
		WorkspaceID: workspaceID, Root: sealedRoot.Ref, Policy: sealedPolicy.Ref,
		Actor: verified.Subject(), OperationID: operationID,
		Provenance: []commitmodel.MutationProvenance{{
			ID: provenanceID, Action: commitmodel.InitializeAction(), Target: sealedRoot.Revision.UID, After: &sealedRoot.Ref,
		}},
		Closure: MergeClosures(sealedRoot.Closure, sealedPolicy.Closure),
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if published.CommitID == "" || len(audit.events) != 2 || audit.events[0].result != AuditResultStarted || audit.events[1].result != AuditResultSucceeded {
		t.Fatalf("published/audit = %#v %#v", published, audit.events)
	}

	commitVerifier, err := registry.NewEncryptedCommitVerifier(remote, device, verifier)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := registry.Discover(context.Background(), workspaceID, remote, commitVerifier)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(discovery.Announcements) != 1 || discovery.Announcements[0].Commit.CommitID != published.CommitID {
		t.Fatalf("Discovery = %#v", discovery)
	}
}

func TestPublisherFailsClosedWhenStartedAuditCannotPersist(t *testing.T) {
	t.Parallel()

	fixture := newPublishFixture(t)
	sentinel := errors.New("audit disk full")
	fixture.publisher.Audit = &recordingAudit{startErr: sentinel}
	if _, err := fixture.publisher.Publish(context.Background(), AuditActionInitialize, fixture.mutation); !errors.Is(err, sentinel) {
		t.Fatalf("Publish = %v, want audit error", err)
	}
	if len(fixture.remote.refs) != 0 {
		t.Fatal("publication became visible without durable started audit")
	}
}

func TestPublisherRecordsFailedTerminalEventOnRemoteFailure(t *testing.T) {
	t.Parallel()

	fixture := newPublishFixture(t)
	sentinel := errors.New("registry unavailable")
	fixture.remote.pushErr = sentinel
	audit := &recordingAudit{}
	fixture.publisher.Audit = audit
	if _, err := fixture.publisher.Publish(context.Background(), AuditActionInitialize, fixture.mutation); !errors.Is(err, sentinel) {
		t.Fatalf("Publish = %v, want remote error", err)
	}
	if len(audit.events) != 2 || audit.events[1].result != AuditResultFailed || len(fixture.remote.refs) != 0 {
		t.Fatalf("audit/refs = %#v %#v", audit.events, fixture.remote.refs)
	}
}

type publishFixture struct {
	publisher Publisher
	mutation  CommitMutation
	remote    *memoryRemote
}

func newPublishFixture(t *testing.T) publishFixture {
	t.Helper()
	local := newMemoryObjects()
	remote := newMemoryRemote()
	device, verified, _ := testDevice(t)
	sealer := Sealer{Sink: local, Issuer: device, Recipients: []artifact.VerifiedDevice{verified}}
	policyType, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/RegoPolicy")
	sealedPolicy, err := sealer.SealPolicyDraft(context.Background(), Draft{Kind: artifact.KindResource, UID: testUUID(t, "61616161-6161-4161-8161-616161616161"), Schema: policyType, Metadata: artifact.Metadata{Name: "policy"}, Payloads: []PayloadSource{{Name: "policy.rego", MediaType: "text/plain", Reader: bytes.NewReader(policy.OwnerOnlyPolicy())}}})
	if err != nil {
		t.Fatal(err)
	}
	rootType, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/ValueTree")
	sealedRoot, err := sealer.SealDraft(context.Background(), Draft{Kind: artifact.KindCollection, UID: testUUID(t, "62626262-6262-4262-8262-626262626262"), Schema: rootType, Metadata: artifact.Metadata{Name: "root"}}, sealedPolicy.Ref.Revision)
	if err != nil {
		t.Fatal(err)
	}
	return publishFixture{
		publisher: Publisher{Local: local, Remote: remote, Device: device, Author: verified, Recipients: []artifact.VerifiedDevice{verified}, Audit: &recordingAudit{}},
		mutation: CommitMutation{
			WorkspaceID: testUUID(t, "63636363-6363-4363-8363-636363636363"), Root: sealedRoot.Ref, Policy: sealedPolicy.Ref,
			Actor: verified.Subject(), OperationID: testUUID(t, "64646464-6464-4464-8464-646464646464"),
			Provenance: []commitmodel.MutationProvenance{{ID: testUUID(t, "65656565-6565-4565-8565-656565656565"), Action: commitmodel.InitializeAction(), Target: sealedRoot.Revision.UID, After: &sealedRoot.Ref}},
			Closure:    MergeClosures(sealedRoot.Closure, sealedPolicy.Closure),
		},
		remote: remote,
	}
}

type auditRecord struct {
	result AuditResult
	digest digest.Digest
}

type recordingAudit struct {
	events    []auditRecord
	startErr  error
	finishErr error
}

func (audit *recordingAudit) Started(_ context.Context, _ artifact.UUID, _ AuditAction, value digest.Digest) error {
	if audit.startErr != nil {
		return audit.startErr
	}
	audit.events = append(audit.events, auditRecord{result: AuditResultStarted, digest: value})
	return nil
}

func (audit *recordingAudit) Finished(_ context.Context, _ artifact.UUID, _ AuditAction, value digest.Digest, result AuditResult) error {
	if audit.finishErr != nil {
		return audit.finishErr
	}
	audit.events = append(audit.events, auditRecord{result: result, digest: value})
	return nil
}

type memoryRemote struct {
	mu      sync.Mutex
	objects map[digest.Digest]storedObject
	refs    []registry.AnnouncementRef
	pushErr error
}

func newMemoryRemote() *memoryRemote { return &memoryRemote{objects: map[digest.Digest]storedObject{}} }

func (remote *memoryRemote) Push(ctx context.Context, expected artifact.Descriptor, reader io.Reader) error {
	if remote.pushErr != nil {
		return remote.pushErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if digest.FromBytes(data) != expected.Digest || int64(len(data)) != expected.Size {
		return errors.New("descriptor mismatch")
	}
	remote.mu.Lock()
	remote.objects[expected.Digest] = storedObject{descriptor: expected, data: append([]byte(nil), data...)}
	remote.mu.Unlock()
	return nil
}

func (remote *memoryRemote) Open(ctx context.Context, value digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	remote.mu.Lock()
	object, ok := remote.objects[value]
	remote.mu.Unlock()
	if !ok {
		return nil, artifact.Descriptor{}, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(object.data)), object.descriptor, nil
}

func (remote *memoryRemote) Has(ctx context.Context, value digest.Digest) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	remote.mu.Lock()
	_, ok := remote.objects[value]
	remote.mu.Unlock()
	return ok, nil
}

func (remote *memoryRemote) PublishAnnouncement(_ context.Context, tag string, descriptor artifact.Descriptor, _ []artifact.Descriptor) error {
	remote.mu.Lock()
	remote.refs = append(remote.refs, registry.AnnouncementRef{Tag: tag, Descriptor: descriptor})
	remote.mu.Unlock()
	return nil
}

func (remote *memoryRemote) ListAnnouncements(_ context.Context, cursor string, limit int, _ *registry.VerificationBudget) (registry.AnnouncementPage, error) {
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if cursor != "" {
		return registry.AnnouncementPage{}, nil
	}
	refs := append([]registry.AnnouncementRef(nil), remote.refs...)
	if len(refs) > limit {
		refs = refs[:limit]
		return registry.AnnouncementPage{Refs: refs, Next: "next"}, nil
	}
	return registry.AnnouncementPage{Refs: refs}, nil
}

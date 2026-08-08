package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/opencontainers/go-digest"
)

func TestEncryptedCommitVerifierSupportsRepublishByAnotherDevice(t *testing.T) {
	t.Parallel()

	fixture := newEncryptedVerifierFixture(t, true)
	verifier, err := NewEncryptedCommitVerifier(fixture.remote, fixture.client.identity, fixture.enrollments)
	if err != nil {
		t.Fatalf("NewEncryptedCommitVerifier: %v", err)
	}
	discovery, err := Discover(context.Background(), fixture.workspaceID, fixture.remote, verifier)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(discovery.Announcements) != 1 || len(discovery.Inaccessible) != 1 || len(discovery.Rejections) != 0 {
		t.Fatalf("Discovery = %#v", discovery)
	}
	got := discovery.Announcements[0].Commit.Value.Commit()
	if got.Actor != fixture.author.subject || got.DeviceID != fixture.author.identity.DeviceID() {
		t.Fatalf("Commit author = %q/%s, want author A", got.Actor, got.DeviceID)
	}
	if discovery.Announcements[0].Announcement.Grant != fixture.accessibleGrant {
		t.Fatal("new device did not select publisher B's accessible rewrap")
	}
	dag, err := discovery.BuildDAG(context.Background())
	if err != nil {
		t.Fatalf("BuildDAG: %v", err)
	}
	if dag.Len() != 1 || dag.Root() != fixture.commitID || len(dag.Frontier()) != 1 || dag.Frontier()[0] != fixture.commitID {
		t.Fatalf("DAG root/frontier = %s/%v", dag.Root(), dag.Frontier())
	}
}

func TestEncryptedCommitVerifierRejectsHostileSiblingWithoutHidingValidCommit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		add  func(*testing.T, *encryptedVerifierFixture)
		code RejectionCode
	}{
		{
			name: "bad publisher signature",
			code: RejectionInvalidSignature,
			add: func(t *testing.T, fixture *encryptedVerifierFixture) {
				bad := fixture.accessibleAnnouncement
				bad.Signature = append([]byte(nil), bad.Signature...)
				bad.Signature[0] ^= 0x80
				publishVerifierAnnouncement(t, fixture, bad)
			},
		},
		{
			name: "Grant material mismatch",
			code: RejectionInvalidCommit,
			add: func(t *testing.T, fixture *encryptedVerifierFixture) {
				identity, err := artifact.GenerateMaterialIdentity()
				if err != nil {
					t.Fatal(err)
				}
				grant, err := artifact.CreateAccessGrant(
					context.Background(), digest.FromString("wrong Commit material"), fixture.policy.Revision,
					identity, fixture.publisher.identity, []artifact.VerifiedDevice{fixture.publisher.verified, fixture.client.verified},
				)
				if err != nil {
					t.Fatal(err)
				}
				grantDescriptor := ingestGrantForVerifierTest(t, fixture.local, grant)
				announcement := newVerifierAnnouncement(t, fixture, fixture.sealed.Descriptor(), grantDescriptor, fixture.commitID)
				publishVerifierAnnouncement(t, fixture, announcement)
			},
		},
		{
			name: "Grant policy mismatch",
			code: RejectionInvalidCommit,
			add: func(t *testing.T, fixture *encryptedVerifierFixture) {
				grant, err := fixture.sealed.CreateAccessGrant(
					context.Background(), digest.FromString("self-authorizing policy"), fixture.publisher.identity,
					[]artifact.VerifiedDevice{fixture.publisher.verified, fixture.client.verified},
				)
				if err != nil {
					t.Fatal(err)
				}
				grantDescriptor := ingestGrantForVerifierTest(t, fixture.local, grant)
				announcement := newVerifierAnnouncement(t, fixture, fixture.sealed.Descriptor(), grantDescriptor, fixture.commitID)
				publishVerifierAnnouncement(t, fixture, announcement)
			},
		},
		{
			name: "malformed encrypted Commit",
			code: RejectionInvalidCommit,
			add: func(t *testing.T, fixture *encryptedVerifierFixture) {
				badCommit, err := fixture.local.Ingest(
					context.Background(), artifact.MediaTypeEncryptedCommit, strings.NewReader("not an age object"),
				)
				if err != nil {
					t.Fatal(err)
				}
				identity, err := artifact.GenerateMaterialIdentity()
				if err != nil {
					t.Fatal(err)
				}
				grant, err := artifact.CreateAccessGrant(
					context.Background(), badCommit.Digest, fixture.policy.Revision, identity,
					fixture.publisher.identity, []artifact.VerifiedDevice{fixture.publisher.verified, fixture.client.verified},
				)
				if err != nil {
					t.Fatal(err)
				}
				grantDescriptor := ingestGrantForVerifierTest(t, fixture.local, grant)
				announcement := newVerifierAnnouncement(t, fixture, badCommit, grantDescriptor, digest.FromString("malformed logical Commit"))
				publishVerifierAnnouncement(t, fixture, announcement)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newEncryptedVerifierFixture(t, false)
			test.add(t, fixture)
			verifier, err := NewEncryptedCommitVerifier(fixture.remote, fixture.client.identity, fixture.enrollments)
			if err != nil {
				t.Fatal(err)
			}
			discovery, err := Discover(context.Background(), fixture.workspaceID, fixture.remote, verifier)
			if err != nil {
				t.Fatalf("Discover: %v", err)
			}
			if len(discovery.Announcements) != 1 || len(discovery.Rejections) != 1 || discovery.Rejections[0].Code != test.code {
				t.Fatalf("Discovery = %#v, want valid sibling plus %s", discovery, test.code)
			}
			if _, err := discovery.BuildDAG(context.Background()); err != nil {
				t.Fatalf("valid sibling DAG: %v", err)
			}
		})
	}
}

func TestEncryptedCommitVerifierRejectsEmbeddedAuthorEnrollmentMismatch(t *testing.T) {
	t.Parallel()

	fixture := newEncryptedVerifierFixture(t, false)
	badEnrollments := fixture.enrollments.clone()
	authorClaims := badEnrollments.claims[string(fixture.author.assertion)]
	authorClaims.Subject = "github:user:substituted-author"
	badEnrollments.claims[string(fixture.author.assertion)] = authorClaims
	verifier, err := NewEncryptedCommitVerifier(fixture.remote, fixture.client.identity, badEnrollments)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := Discover(context.Background(), fixture.workspaceID, fixture.remote, verifier)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	assertSingleRejection(t, discovery, RejectionInvalidCommit)
}

func TestEncryptedCommitVerifierPropagatesTransportFailure(t *testing.T) {
	t.Parallel()

	fixture := newEncryptedVerifierFixture(t, false)
	sentinel := errors.New("registry transport offline")
	fixture.remote.failOpen[fixture.accessibleGrant.Digest] = sentinel
	verifier, err := NewEncryptedCommitVerifier(fixture.remote, fixture.client.identity, fixture.enrollments)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(context.Background(), fixture.workspaceID, fixture.remote, verifier); !errors.Is(err, sentinel) {
		t.Fatalf("Discover error = %v, want transport sentinel", err)
	}
}

func TestEncryptedCommitVerifierPropagatesTerminalCloseFailures(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		descriptor func(*encryptedVerifierFixture) artifact.Descriptor
	}{
		{name: "Grant", descriptor: func(f *encryptedVerifierFixture) artifact.Descriptor { return f.accessibleGrant }},
		{name: "encrypted Commit", descriptor: func(f *encryptedVerifierFixture) artifact.Descriptor { return f.sealed.Descriptor() }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fixture := newEncryptedVerifierFixture(t, false)
			sentinel := errors.New("terminal transport close failed")
			fixture.remote.closeErr[test.descriptor(fixture).Digest] = sentinel
			verifier, err := NewEncryptedCommitVerifier(fixture.remote, fixture.client.identity, fixture.enrollments)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Discover(context.Background(), fixture.workspaceID, fixture.remote, verifier); !errors.Is(err, sentinel) {
				t.Fatalf("Discover close error = %v, want sentinel", err)
			}
		})
	}
}

type verifierDevice struct {
	identity  *artifact.DeviceIdentity
	verified  artifact.VerifiedDevice
	assertion []byte
	subject   string
}

type verifierEnrollments struct {
	claims map[string]artifact.EnrollmentClaims
}

func (v *verifierEnrollments) VerifyEnrollment(_ context.Context, assertion []byte) (artifact.EnrollmentClaims, error) {
	claims, ok := v.claims[string(assertion)]
	if !ok {
		return artifact.EnrollmentClaims{}, errors.New("unknown historical enrollment")
	}
	claims.Ed25519PublicKey = append(ed25519.PublicKey(nil), claims.Ed25519PublicKey...)
	return claims, nil
}

func (v *verifierEnrollments) add(t *testing.T, subject string) verifierDevice {
	t.Helper()
	identity, err := artifact.GenerateDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	assertion := []byte("historical-enrollment:" + string(identity.DeviceID()))
	v.claims[string(assertion)] = artifact.EnrollmentClaims{
		DeviceID:         identity.DeviceID(),
		Subject:          subject,
		X25519Recipient:  identity.RecipientString(),
		Ed25519PublicKey: identity.SigningPublicKey(),
	}
	verified, err := artifact.VerifyEnrollment(context.Background(), v, assertion)
	if err != nil {
		t.Fatal(err)
	}
	return verifierDevice{identity: identity, verified: verified, assertion: assertion, subject: subject}
}

func (v *verifierEnrollments) clone() *verifierEnrollments {
	clone := &verifierEnrollments{claims: make(map[string]artifact.EnrollmentClaims, len(v.claims))}
	for assertion, claims := range v.claims {
		claims.Ed25519PublicKey = append(ed25519.PublicKey(nil), claims.Ed25519PublicKey...)
		clone.claims[assertion] = claims
	}
	return clone
}

type encryptedVerifierFixture struct {
	workspaceID            artifact.UUID
	policy                 artifact.SealedRef
	author                 verifierDevice
	publisher              verifierDevice
	client                 verifierDevice
	enrollments            *verifierEnrollments
	local                  *memoryRemote
	remote                 *memoryRemote
	sealed                 commitmodel.SealedCommit
	commitID               digest.Digest
	accessibleGrant        artifact.Descriptor
	accessibleAnnouncement CommitAnnouncement
}

func newEncryptedVerifierFixture(t *testing.T, includeInaccessible bool) *encryptedVerifierFixture {
	t.Helper()
	enrollments := &verifierEnrollments{claims: make(map[string]artifact.EnrollmentClaims)}
	author := enrollments.add(t, "github:user:author-a")
	publisher := enrollments.add(t, "github:user:publisher-b")
	client := enrollments.add(t, "github:user:client-c")
	workspaceID := mustUUID(t, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	root := artifact.SealedRef{Revision: digest.FromString("integration root revision"), Material: digest.FromString("integration root material"), Grant: digest.FromString("integration root grant")}
	policy := artifact.SealedRef{Revision: digest.FromString("integration policy revision"), Material: digest.FromString("integration policy material"), Grant: digest.FromString("integration policy grant")}
	value := commitmodel.Commit{
		APIVersion:  commitmodel.APIVersion,
		Kind:        commitmodel.Kind,
		WorkspaceID: workspaceID,
		Root:        root,
		Policy:      policy,
		Actor:       author.subject,
		DeviceID:    author.identity.DeviceID(),
		OperationID: mustUUID(t, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		Timestamp:   commitmodel.NewTimestamp(time.Date(2026, time.August, 8, 13, 0, 0, 0, time.UTC)),
		Provenance: []commitmodel.MutationProvenance{{
			ID:     mustUUID(t, "cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
			Action: commitmodel.InitializeAction(),
			Target: mustUUID(t, "dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
			After:  &root,
		}},
	}
	local := newMemoryRemote()
	remote := newMemoryRemote()
	sealed, err := commitmodel.SealCommit(context.Background(), local, value, author.identity, author.verified)
	if err != nil {
		t.Fatalf("SealCommit: %v", err)
	}
	fixture := &encryptedVerifierFixture{
		workspaceID: workspaceID,
		policy:      policy,
		author:      author,
		publisher:   publisher,
		client:      client,
		enrollments: enrollments,
		local:       local,
		remote:      remote,
		sealed:      sealed,
		commitID:    sealed.CommitID(),
	}

	if includeInaccessible {
		oldGrant, err := sealed.CreateAccessGrant(context.Background(), policy.Revision, author.identity, []artifact.VerifiedDevice{author.verified})
		if err != nil {
			t.Fatal(err)
		}
		oldGrantDescriptor := ingestGrantForVerifierTest(t, local, oldGrant)
		oldAnnouncement, err := NewCommitAnnouncement(workspaceID, sealed.CommitID(), sealed.Descriptor(), oldGrantDescriptor, author.identity, author.verified)
		if err != nil {
			t.Fatal(err)
		}
		publishVerifierAnnouncement(t, fixture, oldAnnouncement)
	}

	grant, err := sealed.CreateAccessGrant(
		context.Background(), policy.Revision, publisher.identity,
		[]artifact.VerifiedDevice{publisher.verified, client.verified},
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.accessibleGrant = ingestGrantForVerifierTest(t, local, grant)
	fixture.accessibleAnnouncement = newVerifierAnnouncement(t, fixture, sealed.Descriptor(), fixture.accessibleGrant, sealed.CommitID())
	publishVerifierAnnouncement(t, fixture, fixture.accessibleAnnouncement)
	return fixture
}

func ingestGrantForVerifierTest(t *testing.T, objects *memoryRemote, grant artifact.AccessGrant) artifact.Descriptor {
	t.Helper()
	encoded, err := artifact.EncodeAccessGrant(grant)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := objects.Ingest(context.Background(), artifact.MediaTypeAccessGrant, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func newVerifierAnnouncement(
	t *testing.T,
	fixture *encryptedVerifierFixture,
	encryptedCommit artifact.Descriptor,
	grant artifact.Descriptor,
	commitID digest.Digest,
) CommitAnnouncement {
	t.Helper()
	announcement, err := NewCommitAnnouncement(
		fixture.workspaceID, commitID, encryptedCommit, grant, fixture.publisher.identity, fixture.publisher.verified,
	)
	if err != nil {
		t.Fatal(err)
	}
	return announcement
}

func publishVerifierAnnouncement(t *testing.T, fixture *encryptedVerifierFixture, announcement CommitAnnouncement) {
	t.Helper()
	if _, err := Publish(context.Background(), fixture.remote, fixture.local, PublicationClosure{}, announcement); err != nil {
		t.Fatalf("Publish: %v", err)
	}
}

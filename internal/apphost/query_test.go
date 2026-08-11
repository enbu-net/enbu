package apphost

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"sort"
	"testing"

	"github.com/enbu-net/enbu/pkg/artifact"
	commitmodel "github.com/enbu-net/enbu/pkg/commit"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/opencontainers/go-digest"
)

type queryIdentity struct {
	workspace artifact.UUID
	root      string
	revision  digest.Digest
}

func (identity queryIdentity) WorkspaceID() artifact.UUID    { return identity.workspace }
func (identity queryIdentity) Root() string                  { return identity.root }
func (identity queryIdentity) ConfigRevision() digest.Digest { return identity.revision }

type queryFixture struct {
	runtime       *Runtime
	session       *Session
	execution     queryIdentity
	initialCommit digest.Digest
	latestCommit  digest.Digest
	initialRoot   artifact.UUID
	created       []artifact.UUID
}

func TestExecutorQueriesPinnedDeterministicMetadataWithoutPayloads(t *testing.T) {
	fixture := newQueryFixture(t)
	ctx := context.Background()

	snapshot, err := fixture.runtime.executor.Snapshot(ctx, fixture.execution)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.Frontier) != 1 || snapshot.Frontier[0] != fixture.latestCommit || snapshot.ResourceCount != 3 || snapshot.CommitCount != 2 {
		t.Fatalf("Snapshot = %#v", snapshot)
	}

	// A Commit pin selects its immutable graph even after the remote frontier
	// has advanced.
	initial, err := fixture.runtime.executor.ListResources(ctx, fixture.execution, host.ResourcePageQuery{
		AtCommit: fixture.initialCommit, Limit: host.MaxQueryPageSize,
	})
	if err != nil {
		t.Fatalf("ListResources(initial): %v", err)
	}
	if initial.More || initial.NextOffset != 0 || len(initial.Resources) != 1 || initial.Resources[0].UID != fixture.initialRoot {
		t.Fatalf("initial resources = %#v", initial)
	}

	var resources []host.ResourceMetadata
	offset := uint64(0)
	for {
		page, pageErr := fixture.runtime.executor.ListResources(ctx, fixture.execution, host.ResourcePageQuery{
			AtCommit: fixture.latestCommit, Offset: offset, Limit: 1,
		})
		if pageErr != nil {
			t.Fatalf("ListResources(offset %d): %v", offset, pageErr)
		}
		resources = append(resources, page.Resources...)
		if !page.More {
			if page.NextOffset != 0 {
				t.Fatalf("terminal NextOffset = %d", page.NextOffset)
			}
			break
		}
		if page.NextOffset <= offset {
			t.Fatalf("non-advancing offset: %d -> %d", offset, page.NextOffset)
		}
		offset = page.NextOffset
	}
	if len(resources) != 3 {
		t.Fatalf("resources = %#v", resources)
	}
	for index := 1; index < len(resources); index++ {
		if resources[index-1].UID >= resources[index].UID {
			t.Fatalf("resources are not sorted by UID: %#v", resources)
		}
	}

	secretUID := fixture.created[0]
	resource, err := fixture.runtime.executor.GetResource(ctx, fixture.execution, host.ResourceQuery{
		AtCommit: fixture.latestCommit, UID: secretUID,
	})
	if err != nil {
		t.Fatalf("GetResource: %v", err)
	}
	if resource.Metadata.Name != "firmware-wifi" || resource.Metadata.Labels["device"] != "router" || resource.Metadata.Annotations["source"] != "firmware" {
		t.Fatalf("resource metadata = %#v", resource)
	}
	// ResourceMetadata has no payload field; changing its returned maps must not
	// mutate authenticated graph state retained by the executor.
	resource.Metadata.Labels["device"] = "mutated"
	resource.Metadata.Annotations["source"] = "mutated"
	again, err := fixture.runtime.executor.GetResource(ctx, fixture.execution, host.ResourceQuery{
		AtCommit: fixture.latestCommit, UID: secretUID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.Metadata.Labels["device"] != "router" || again.Metadata.Annotations["source"] != "firmware" {
		t.Fatalf("metadata was aliased: %#v", again.Metadata)
	}

	missing := mustQueryUUID(t, "ffffffff-ffff-4fff-8fff-ffffffffffff")
	if _, err := fixture.runtime.executor.GetResource(ctx, fixture.execution, host.ResourceQuery{AtCommit: fixture.latestCommit, UID: missing}); !errors.Is(err, host.ErrResourceNotFound) {
		t.Fatalf("GetResource(missing) = %v", err)
	}
	if _, err := fixture.runtime.executor.ListResources(ctx, fixture.execution, host.ResourcePageQuery{AtCommit: digest.FromString("unknown"), Limit: 1}); !errors.Is(err, commitmodel.ErrCommitNotFound) {
		t.Fatalf("ListResources(unknown Commit) = %v", err)
	}
}

func TestExecutorCommitQueryUsesStableAntichainFrontier(t *testing.T) {
	fixture := newQueryFixture(t)
	ctx := context.Background()

	var commits []host.CommitMetadata
	offset := uint64(0)
	for {
		page, err := fixture.runtime.executor.ListCommits(ctx, fixture.execution, host.CommitPageQuery{
			Frontier: []digest.Digest{fixture.latestCommit}, Offset: offset, Limit: 1,
		})
		if err != nil {
			t.Fatalf("ListCommits(offset %d): %v", offset, err)
		}
		commits = append(commits, page.Commits...)
		if !page.More {
			break
		}
		offset = page.NextOffset
	}
	if len(commits) != 2 {
		t.Fatalf("commits = %#v", commits)
	}
	if commits[0].ID >= commits[1].ID {
		t.Fatalf("commits are not sorted by digest: %#v", commits)
	}
	if len(commits[0].Parents) != 0 && len(commits[1].Parents) != 0 {
		t.Fatalf("no initialization Commit in %#v", commits)
	}

	// The prior frontier remains a valid immutable history pin after a child is
	// published. This is required for stable pagination across concurrent syncs.
	old, err := fixture.runtime.executor.ListCommits(ctx, fixture.execution, host.CommitPageQuery{
		Frontier: []digest.Digest{fixture.initialCommit}, Limit: host.MaxQueryPageSize,
	})
	if err != nil {
		t.Fatalf("ListCommits(old frontier): %v", err)
	}
	if old.More || len(old.Commits) != 1 || old.Commits[0].ID != fixture.initialCommit {
		t.Fatalf("old frontier page = %#v", old)
	}

	// A frontier must be an antichain; listing both a descendant and its
	// ancestor is not an exact frontier pin.
	if _, err := fixture.runtime.executor.ListCommits(ctx, fixture.execution, host.CommitPageQuery{
		Frontier: []digest.Digest{fixture.latestCommit, fixture.initialCommit}, Limit: 10,
	}); !errors.Is(err, host.ErrInvalidQuery) {
		t.Fatalf("ListCommits(redundant frontier) = %v", err)
	}

	// Parent slices returned from one query are defensive copies.
	for index := range commits {
		if len(commits[index].Parents) != 0 {
			commits[index].Parents[0] = digest.FromString("mutated")
		}
	}
	again, err := fixture.runtime.executor.ListCommits(ctx, fixture.execution, host.CommitPageQuery{
		Frontier: []digest.Digest{fixture.latestCommit}, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	foundChild := false
	for _, value := range again.Commits {
		if value.ID == fixture.latestCommit {
			foundChild = len(value.Parents) == 1 && value.Parents[0] == fixture.initialCommit
		}
	}
	if !foundChild {
		t.Fatalf("Commit parents were aliased: %#v", again.Commits)
	}
}

func TestExecutorQueriesValidateExecutionAndPagination(t *testing.T) {
	fixture := newQueryFixture(t)
	ctx := context.Background()

	wrongRoot := fixture.execution
	wrongRoot.root += "-other"
	if _, err := fixture.runtime.executor.Snapshot(ctx, wrongRoot); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Snapshot(wrong root) = %v", err)
	}
	wrongRevision := fixture.execution
	wrongRevision.revision = digest.FromString("other config")
	if _, err := fixture.runtime.executor.Snapshot(ctx, wrongRevision); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Snapshot(wrong revision) = %v", err)
	}
	wrongWorkspace := fixture.execution
	wrongWorkspace.workspace = mustQueryUUID(t, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	if _, err := fixture.runtime.executor.Snapshot(ctx, wrongWorkspace); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Snapshot(wrong workspace) = %v", err)
	}
	if _, err := fixture.runtime.executor.Snapshot(nil, fixture.execution); err == nil { //nolint:staticcheck // nil-context rejection is the behavior under test.
		t.Fatal("Snapshot(nil context) succeeded")
	}

	invalidPages := []host.ResourcePageQuery{
		{AtCommit: fixture.latestCommit, Limit: 0},
		{AtCommit: fixture.latestCommit, Limit: host.MaxQueryPageSize + 1},
		{AtCommit: fixture.latestCommit, Offset: math.MaxUint64, Limit: 1},
		{AtCommit: fixture.latestCommit, Offset: 4, Limit: 1},
	}
	for _, query := range invalidPages {
		if _, err := fixture.runtime.executor.ListResources(ctx, fixture.execution, query); !errors.Is(err, host.ErrInvalidQuery) {
			t.Fatalf("ListResources(%#v) = %v", query, err)
		}
	}
}

func newQueryFixture(t *testing.T) queryFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	runtime, err := New(Dependencies{
		Credentials: newTestCredentials(),
		Remotes:     testRemoteProvider{remote: newTestRemote()},
		Audits:      &testAuditFactory{},
		DataDir:     filepath.Join(t.TempDir(), "state"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	session, initialization, err := runtime.Initialize(ctx, InitializeRequest{
		Root: root, Registry: "registry.example/team/enbu", Subject: "github:query-test",
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := session.Close(context.Background()); closeErr != nil {
			t.Errorf("Session.Close: %v", closeErr)
		}
		if closeErr := runtime.Close(context.Background()); closeErr != nil {
			t.Errorf("Runtime.Close: %v", closeErr)
		}
	})
	initialized, err := session.Workspace().Wait(ctx, initialization)
	if err != nil || initialized.Initialize == nil {
		t.Fatalf("Wait(initialization) = %#v, %v", initialized, err)
	}

	execution := queryIdentity{
		workspace: session.state.config.Workspace,
		root:      session.state.root,
		revision:  session.state.revision,
	}
	initialPage, err := runtime.executor.ListResources(ctx, execution, host.ResourcePageQuery{
		AtCommit: initialized.Initialize.Commit, Limit: 10,
	})
	if err != nil || len(initialPage.Resources) != 1 {
		t.Fatalf("initial ListResources = %#v, %v", initialPage, err)
	}

	secretInput, err := session.Workspace().RegisterInput(ctx, &fixedInputSource{data: []byte("ssid=office\npass=not-for-query")})
	if err != nil {
		t.Fatalf("RegisterInput: %v", err)
	}
	keyInput, err := session.Workspace().RegisterInput(ctx, &fixedInputSource{data: []byte("-----BEGIN PRIVATE KEY-----\nnot-for-query")})
	if err != nil {
		t.Fatalf("RegisterInput(key): %v", err)
	}
	opaque, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Opaque")
	secretUID := mustQueryUUID(t, "11111111-1111-4111-8111-111111111111")
	keyUID := mustQueryUUID(t, "22222222-2222-4222-8222-222222222222")
	operation, err := session.Workspace().Start(ctx, host.ApplyAction{
		BaseCommit: initialized.Initialize.Commit,
		Changes: []host.GraphChange{
			{Create: &host.CreateResource{Draft: host.DraftResource{
				Kind: artifact.KindResource, UID: secretUID, Schema: opaque,
				Metadata: artifact.Metadata{
					Name: "firmware-wifi", Labels: map[string]string{"device": "router"},
					Annotations: map[string]string{"source": "firmware"},
				},
				Payloads: []host.StagedPayload{{Name: "firmware.bin", MediaType: "application/octet-stream", Source: secretInput}},
			}}},
			{Create: &host.CreateResource{Draft: host.DraftResource{
				Kind: artifact.KindResource, UID: keyUID, Schema: opaque,
				Metadata: artifact.Metadata{Name: "ssh-private-key", Labels: map[string]string{"device": "laptop"}},
				Payloads: []host.StagedPayload{{Name: "id_ed25519", MediaType: "application/x-pem-file", Source: keyInput}},
			}}},
		},
	})
	if err != nil {
		t.Fatalf("Start(Apply): %v", err)
	}
	applied, err := session.Workspace().Wait(ctx, operation)
	if err != nil || applied.Commit == nil {
		t.Fatalf("Wait(Apply) = %#v, %v", applied, err)
	}

	created := []artifact.UUID{secretUID, keyUID}
	sort.Slice(created, func(left, right int) bool { return created[left] < created[right] })
	return queryFixture{
		runtime: runtime, session: session, execution: execution,
		initialCommit: initialized.Initialize.Commit, latestCommit: applied.Commit.Commit,
		initialRoot: initialPage.Resources[0].UID, created: created,
	}
}

func mustQueryUUID(t *testing.T, value string) artifact.UUID {
	t.Helper()
	parsed, err := artifact.ParseUUID(value)
	if err != nil {
		t.Fatalf("ParseUUID(%q): %v", value, err)
	}
	return parsed
}

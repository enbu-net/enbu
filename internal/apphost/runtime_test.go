package apphost

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/cas"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/policy"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/enbu-net/enbu/pkg/schema"
	"github.com/enbu-net/enbu/pkg/workspace"
	"github.com/opencontainers/go-digest"
)

func TestRuntimeInitializationCreatesDiscoverableV1CommitAndReopens(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	dataDir := filepath.Join(t.TempDir(), "state")
	credentials := newTestCredentials()
	remote := newTestRemote()
	audits := &testAuditFactory{}
	runtime, err := New(Dependencies{
		Credentials: credentials,
		Remotes:     testRemoteProvider{remote: remote},
		Audits:      audits,
		DataDir:     dataDir,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	session, operation, err := runtime.Initialize(context.Background(), InitializeRequest{
		Root: root, Registry: "registry.example/team/enbu", Subject: "github:12345",
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	outcome, err := session.Workspace().Wait(context.Background(), operation)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if outcome.Initialize == nil || outcome.Initialize.Commit == "" {
		t.Fatalf("Outcome = %#v", outcome)
	}
	config, _, err := workspace.Load(root)
	if err != nil {
		t.Fatalf("workspace.Load: %v", err)
	}
	if config.Workspace != outcome.Initialize.WorkspaceID || len(remote.refs) != 1 {
		t.Fatalf("config/remote = %#v %#v", config, remote.refs)
	}
	if len(audits.trails) != 1 || len(audits.trails[0].events) != 2 || audits.trails[0].events[0].result != engine.AuditResultStarted || audits.trails[0].events[1].result != engine.AuditResultSucceeded {
		t.Fatalf("audit = %#v", audits.trails)
	}
	if err := session.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	reopenedRuntime, err := New(Dependencies{Credentials: credentials, Remotes: testRemoteProvider{remote: remote}, Audits: audits, DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := reopenedRuntime.Open(context.Background(), root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if reopened.Workspace().ID() == "" {
		t.Fatal("reopened session has no capability ID")
	}
	_ = reopened.Close(context.Background())
	_ = reopenedRuntime.Close(context.Background())
}

func TestRuntimeInitializationResumesAfterAnnouncementFailure(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	dataDir := filepath.Join(t.TempDir(), "state")
	credentials := newTestCredentials()
	remote := newTestRemote()
	remote.publishFailures = 1
	audits := &testAuditFactory{}
	dependencies := Dependencies{
		Credentials: credentials, Remotes: testRemoteProvider{remote: remote}, Audits: audits, DataDir: dataDir,
	}
	first, err := New(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	request := InitializeRequest{Root: root, Registry: "registry.example/team/enbu", Subject: "github:12345"}
	failedSession, failedOperation, err := first.Initialize(context.Background(), request)
	if err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	if _, err := failedSession.Workspace().Wait(context.Background(), failedOperation); err == nil {
		t.Fatal("first initialization unexpectedly succeeded")
	}
	config, _, err := workspace.Load(root)
	if err != nil {
		t.Fatalf("durable config after failure: %v", err)
	}
	if err := failedSession.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	second, err := New(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	resumedSession, resumedOperation, err := second.Initialize(context.Background(), request)
	if err != nil {
		t.Fatalf("resumed Initialize: %v", err)
	}
	outcome, err := resumedSession.Workspace().Wait(context.Background(), resumedOperation)
	if err != nil {
		t.Fatalf("resumed Wait: %v", err)
	}
	if outcome.Initialize == nil || outcome.Initialize.WorkspaceID != config.Workspace {
		t.Fatalf("resumed outcome = %#v, durable workspace = %s", outcome, config.Workspace)
	}
	remote.mu.Lock()
	announcementCount := len(remote.refs)
	remote.mu.Unlock()
	if announcementCount != 1 {
		t.Fatalf("published announcements = %d, want exactly one", announcementCount)
	}
	_ = resumedSession.Close(context.Background())
	_ = second.Close(context.Background())
}

func TestRuntimeDotEnvTransformAndMaterializeEndToEnd(t *testing.T) {
	t.Parallel()

	remote := newTestRemote()
	runtime, err := New(Dependencies{
		Credentials: newTestCredentials(), Remotes: testRemoteProvider{remote: remote},
		Audits: &testAuditFactory{}, DataDir: filepath.Join(t.TempDir(), "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	session, initialization, err := runtime.Initialize(context.Background(), InitializeRequest{
		Root: t.TempDir(), Registry: "registry.example/team/enbu", Subject: "github:12345",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialized, err := session.Workspace().Wait(context.Background(), initialization)
	if err != nil {
		t.Fatal(err)
	}
	page, err := session.Workspace().ListResources(context.Background(), host.ListResourcesRequest{
		AtCommit: initialized.Initialize.Commit, PageSize: host.MaxQueryPageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	var root host.ResourceMetadata
	for _, resource := range page.Resources {
		if resource.Kind == artifact.KindCollection {
			root = resource
			break
		}
	}
	if root.UID == "" {
		t.Fatalf("workspace root not returned: %#v", page.Resources)
	}
	input, err := session.Workspace().RegisterInput(context.Background(), &fixedInputSource{data: []byte("B=two\nA=one\n")})
	if err != nil {
		t.Fatal(err)
	}
	outputUID, _ := newUUID()
	edgeID, _ := newUUID()
	transformType, _ := artifact.ParseTypeRef("transforms.enbu.net/v1alpha1/DotEnvImport")
	operation, err := session.Workspace().Start(context.Background(), host.TransformAction{
		BaseCommit: initialized.Initialize.Commit,
		Transform:  host.TransformRef{Builtin: transformType},
		Parameters: []host.TransformParameter{{Name: "dotenv", Source: input}},
		Outputs: []host.TransformOutput{{
			Slot: "dotenv", UID: outputUID, Metadata: artifact.Metadata{Name: "application-secrets"},
			Parent: root.UID, ExpectedParent: root.Sealed, EdgeID: edgeID, EdgeName: "application-secrets",
			Relation: artifact.MemberRelation(),
			Payloads: []host.TransformPayload{{Name: "secrets.env", MediaType: "text/plain"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	transformed, err := session.Workspace().Wait(context.Background(), operation)
	if err != nil {
		t.Fatalf("transform Wait: %v", err)
	}
	if transformed.Commit == nil || transformed.Commit.Commit == "" {
		t.Fatalf("transform outcome = %#v", transformed)
	}

	materialized := &testTransactionalOutput{}
	destination, err := session.Workspace().RegisterOutput(context.Background(), testOutputTarget{output: materialized})
	if err != nil {
		t.Fatal(err)
	}
	dotenv, _ := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/DotEnv")
	materializeOperation, err := session.Workspace().Start(context.Background(), host.MaterializeAction{
		AtCommit: transformed.Commit.Commit, Target: outputUID, Format: dotenv, Destination: destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Workspace().Wait(context.Background(), materializeOperation); err != nil {
		t.Fatalf("materialize Wait: %v", err)
	}
	if !materialized.committed || materialized.aborted || materialized.String() != "A=\"one\"\nB=\"two\"\n" {
		t.Fatalf("materialized output = %q committed=%v aborted=%v", materialized.String(), materialized.committed, materialized.aborted)
	}
	_ = session.Close(context.Background())
	_ = runtime.Close(context.Background())
}

func TestRuntimeChangesPinnedPolicyAndRejectsStaleBase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runtime, err := New(Dependencies{
		Credentials: newTestCredentials(), Remotes: testRemoteProvider{remote: newTestRemote()},
		Audits: &testAuditFactory{}, DataDir: filepath.Join(t.TempDir(), "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	session, initialization, err := runtime.Initialize(ctx, InitializeRequest{
		Root: t.TempDir(), Registry: "registry.example/team/enbu", Subject: "github:owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialized, err := session.Workspace().Wait(ctx, initialization)
	if err != nil {
		t.Fatal(err)
	}
	dag, err := runtime.executor.completeDAG(ctx, session.state)
	if err != nil {
		t.Fatal(err)
	}
	base, ok := dag.Commit(initialized.Initialize.Commit)
	if !ok {
		t.Fatal("initialized Commit missing")
	}
	opened, err := engine.OpenRevision(ctx, fallbackSource{local: session.state.objects, remote: session.state.remote}, session.state.device, session.state.verifier, base.Policy)
	if err != nil {
		t.Fatal(err)
	}
	policyInput, err := session.Workspace().RegisterInput(ctx, &fixedInputSource{data: append(policy.OwnerOnlyPolicy(), []byte("\n# replacement\n")...)})
	if err != nil {
		t.Fatal(err)
	}
	rego, _ := artifact.ParseTypeRef(schema.SchemaRegoPolicy)
	operation, err := session.Workspace().Start(ctx, host.ChangePolicyAction{
		BaseCommit: initialized.Initialize.Commit,
		Expected:   base.Policy,
		Policy: host.DraftResource{
			Kind: artifact.KindResource, UID: opened.Revision.UID, Schema: rego,
			Metadata: opened.Revision.Metadata,
			Payloads: []host.StagedPayload{{Name: "policy.rego", MediaType: "text/plain", Source: policyInput}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := session.Workspace().Wait(ctx, operation)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Commit == nil || changed.Commit.Commit == initialized.Initialize.Commit {
		t.Fatalf("change policy outcome = %#v", changed)
	}
	commits, err := session.Workspace().ListCommits(ctx, host.ListCommitsRequest{
		Frontier: []digest.Digest{changed.Commit.Commit}, PageSize: host.MaxQueryPageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	var replacement artifact.SealedRef
	for _, commit := range commits.Commits {
		if commit.ID == changed.Commit.Commit {
			replacement = commit.Policy
		}
	}
	if replacement == (artifact.SealedRef{}) || replacement == base.Policy {
		t.Fatalf("replacement policy = %#v", replacement)
	}

	staleInput, err := session.Workspace().RegisterInput(ctx, &fixedInputSource{data: append(policy.OwnerOnlyPolicy(), []byte("\n# stale\n")...)})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := session.Workspace().Start(ctx, host.ChangePolicyAction{
		BaseCommit: initialized.Initialize.Commit, Expected: base.Policy,
		Policy: host.DraftResource{Kind: artifact.KindResource, UID: opened.Revision.UID, Schema: rego,
			Metadata: opened.Revision.Metadata, Payloads: []host.StagedPayload{{Name: "policy.rego", MediaType: "text/plain", Source: staleInput}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	staleOutcome, err := session.Workspace().Wait(ctx, stale)
	if err != nil {
		t.Fatal(err)
	}
	if staleOutcome.Conflict == nil || len(staleOutcome.Conflict.Conflicts) == 0 || staleOutcome.Conflict.Conflicts[0].Kind != host.ConflictPolicy {
		t.Fatalf("stale policy outcome = %#v", staleOutcome)
	}
	_ = session.Close(ctx)
	_ = runtime.Close(ctx)
}

func TestRuntimeEnrollsSecondDeviceAndPublishesCompleteHistoryAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	remote := newTestRemote()
	ownerRoot := t.TempDir()
	owner, err := New(Dependencies{
		Credentials: newTestCredentials(), Remotes: testRemoteProvider{remote: remote},
		Audits: &testAuditFactory{}, DataDir: filepath.Join(t.TempDir(), "owner-state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ownerSession, initialization, err := owner.Initialize(ctx, InitializeRequest{
		Root: ownerRoot, Registry: "registry.example/team/enbu", Subject: "github:owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialized, err := ownerSession.Workspace().Wait(ctx, initialization)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := ownerSession.Workspace().ListResources(ctx, host.ListResourcesRequest{
		AtCommit: initialized.Initialize.Commit, PageSize: host.MaxQueryPageSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	var rootResource host.ResourceMetadata
	for _, resource := range resources.Resources {
		if resource.Kind == artifact.KindCollection {
			rootResource = resource
			break
		}
	}
	if rootResource.UID == "" {
		t.Fatal("initial root resource not found")
	}

	candidateRoot := t.TempDir()
	config, _, err := workspace.Load(ownerRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.SaveNew(candidateRoot, config); err != nil {
		t.Fatal(err)
	}
	candidate, err := New(Dependencies{
		Credentials: newTestCredentials(), Remotes: testRemoteProvider{remote: remote},
		Audits: &testAuditFactory{}, DataDir: filepath.Join(t.TempDir(), "candidate-state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := candidate.CreateEnrollmentRequest(ctx, "github:candidate")
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := owner.ApproveEnrollment(ctx, ownerRoot, request, "github:candidate")
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.ImportEnrollment(ctx, candidateRoot, assertion); err != nil {
		t.Fatal(err)
	}

	change, err := ownerSession.Workspace().Start(ctx, host.ChangeAccessAction{
		BaseCommit: initialized.Initialize.Commit,
		Targets:    []artifact.UUID{rootResource.UID},
		Mode:       host.AccessGrant,
		Candidates: []host.EnrollmentRef{{Digest: digest.FromBytes(assertion)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ownerSession.Workspace().Wait(ctx, change)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Commit == nil {
		t.Fatalf("change access outcome = %#v", changed)
	}

	candidateSession, err := candidate.Open(ctx, candidateRoot)
	if err != nil {
		t.Fatalf("candidate Open after access grant: %v", err)
	}
	snapshot, err := candidateSession.Workspace().Snapshot(ctx)
	if err != nil {
		t.Fatalf("candidate Snapshot: %v", err)
	}
	if len(snapshot.Frontier) != 1 || snapshot.Frontier[0] != changed.Commit.Commit {
		t.Fatalf("candidate frontier = %v, want %s", snapshot.Frontier, changed.Commit.Commit)
	}

	_ = candidateSession.Close(ctx)
	_ = candidate.Close(ctx)
	_ = ownerSession.Close(ctx)
	_ = owner.Close(ctx)
}

func TestRuntimeFileTreeImportAndTarMaterializeEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	runtime, err := New(Dependencies{
		Credentials: newTestCredentials(), Remotes: testRemoteProvider{remote: newTestRemote()},
		Audits: &testAuditFactory{}, DataDir: filepath.Join(t.TempDir(), "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	session, initialization, err := runtime.Initialize(ctx, InitializeRequest{
		Root: t.TempDir(), Registry: "registry.example/team/enbu", Subject: "github:owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	initialized, err := session.Workspace().Wait(ctx, initialization)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := session.Workspace().ListResources(ctx, host.ListResourcesRequest{AtCommit: initialized.Initialize.Commit, PageSize: host.MaxQueryPageSize})
	if err != nil {
		t.Fatal(err)
	}
	var root host.ResourceMetadata
	for _, resource := range resources.Resources {
		if resource.Kind == artifact.KindCollection {
			root = resource
		}
	}
	first, err := session.Workspace().RegisterInput(ctx, &fixedInputSource{data: []byte("ssid=lab\n")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.Workspace().RegisterInput(ctx, &fixedInputSource{data: []byte("PRIVATE KEY\n")})
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := newUUID()
	edgeID, _ := newUUID()
	fileTreeImport, _ := artifact.ParseTypeRef("transforms.enbu.net/v1alpha1/FileTreeImport")
	operation, err := session.Workspace().Start(ctx, host.TransformAction{
		BaseCommit: initialized.Initialize.Commit, Transform: host.TransformRef{Builtin: fileTreeImport},
		Parameters: []host.TransformParameter{{Name: "device/wifi.conf", Source: first}, {Name: "keys/id_ed25519", Source: second}},
		Outputs: []host.TransformOutput{{
			Slot: "tree", UID: uid, Metadata: artifact.Metadata{Name: "device-files"}, Parent: root.UID,
			ExpectedParent: root.Sealed, EdgeID: edgeID, EdgeName: "device-files", Relation: artifact.MemberRelation(),
			Payloads: []host.TransformPayload{
				{Name: "file-0001", MediaType: "application/octet-stream"},
				{Name: "file-0002", MediaType: "application/octet-stream"},
				{Name: schema.FileTreeIndexPayloadName, MediaType: schema.FileTreeIndexMediaType},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	transformed, err := session.Workspace().Wait(ctx, operation)
	if err != nil {
		t.Fatal(err)
	}
	output := &testTransactionalOutput{}
	destination, err := session.Workspace().RegisterOutput(ctx, testOutputTarget{output: output})
	if err != nil {
		t.Fatal(err)
	}
	fileTreeTar, _ := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/FileTreeTar")
	materialization, err := session.Workspace().Start(ctx, host.MaterializeAction{
		AtCommit: transformed.Commit.Commit, Target: uid, Format: fileTreeTar, Destination: destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.Workspace().Wait(ctx, materialization); err != nil {
		t.Fatal(err)
	}
	archive := tar.NewReader(bytes.NewReader(output.Bytes()))
	want := map[string]string{"device/wifi.conf": "ssid=lab\n", "keys/id_ed25519": "PRIVATE KEY\n"}
	for range len(want) {
		header, err := archive.Next()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != want[header.Name] || header.Mode != 0o600 {
			t.Fatalf("tar entry %q mode=%o body=%q", header.Name, header.Mode, body)
		}
		delete(want, header.Name)
	}
	if len(want) != 0 || !output.committed || output.aborted {
		t.Fatalf("remaining=%v committed=%v aborted=%v", want, output.committed, output.aborted)
	}
	_ = session.Close(ctx)
	_ = runtime.Close(ctx)
}

func TestRuntimeRejectsLegacyBeforeCredentialOrRegistryMutation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "enbu.toml"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials := newTestCredentials()
	remote := newTestRemote()
	runtime, err := New(Dependencies{Credentials: credentials, Remotes: testRemoteProvider{remote: remote}, Audits: &testAuditFactory{}, DataDir: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runtime.Initialize(context.Background(), InitializeRequest{Root: root, Registry: "registry.example/team/enbu", Subject: "github:123"}); !errors.Is(err, workspace.ErrLegacyConfig) {
		t.Fatalf("Initialize = %v, want legacy rejection", err)
	}
	credentials.mu.Lock()
	credentialCount := len(credentials.values)
	credentials.mu.Unlock()
	if credentialCount != 0 || len(remote.objects) != 0 || len(remote.refs) != 0 {
		t.Fatal("legacy rejection mutated credentials or registry")
	}
}

type blockingCloseExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (executor *blockingCloseExecutor) Execute(ctx context.Context, _ host.Execution, _ host.Action) (host.Outcome, error) {
	close(executor.started)
	<-executor.release
	if err := ctx.Err(); err != nil {
		return host.Outcome{}, err
	}
	return host.Outcome{Commit: &host.CommitResult{
		Commit: digest.FromString("close-test-commit"),
		Root: artifact.SealedRef{
			Revision: digest.FromString("close-test-revision"),
			Material: digest.FromString("close-test-material"),
			Grant:    digest.FromString("close-test-grant"),
		},
	}}, nil
}

func (*blockingCloseExecutor) Finalize(context.Context, host.Execution, host.Action, host.Outcome, error) error {
	return nil
}

type emptyQueryExecutor struct{}

func (emptyQueryExecutor) Snapshot(context.Context, host.QueryExecution) (host.SnapshotData, error) {
	return host.SnapshotData{}, nil
}

func (emptyQueryExecutor) ListResources(context.Context, host.QueryExecution, host.ResourcePageQuery) (host.ResourcePageData, error) {
	return host.ResourcePageData{}, nil
}

func (emptyQueryExecutor) ListCommits(context.Context, host.QueryExecution, host.CommitPageQuery) (host.CommitPageData, error) {
	return host.CommitPageData{}, nil
}

func (emptyQueryExecutor) GetResource(context.Context, host.QueryExecution, host.ResourceQuery) (host.ResourceMetadata, error) {
	return host.ResourceMetadata{}, host.ErrResourceNotFound
}

func TestRuntimeCloseCanRetryAfterDrainTimeout(t *testing.T) {
	t.Parallel()

	execution := &blockingCloseExecutor{started: make(chan struct{}), release: make(chan struct{})}
	typedHost, err := host.New(execution, emptyQueryExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{host: typedHost, executor: newExecutor()}
	workspaceSession, err := typedHost.OpenWorkspace(context.Background(), host.OpenWorkspaceRequest{
		WorkspaceID: artifact.UUID("11111111-1111-4111-8111-111111111111"),
		Root:        t.TempDir(), ConfigRevision: digest.FromString("close-test-config"),
	})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := workspaceSession.Start(context.Background(), host.RestoreAction{
		BaseCommit: digest.FromString("close-test-base"), SourceCommit: digest.FromString("close-test-source"),
	})
	if err != nil {
		t.Fatal(err)
	}
	<-execution.started

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Close(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("first Close = %v", err)
	}
	close(execution.release)
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("retry Close = %v", err)
	}
	if _, err := workspaceSession.Wait(context.Background(), operation); !errors.Is(err, context.Canceled) {
		t.Fatalf("drained operation = %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close = %v", err)
	}
}

type testCredentials struct {
	mu     sync.Mutex
	values map[string][]byte
}

func newTestCredentials() *testCredentials { return &testCredentials{values: map[string][]byte{}} }
func (*testCredentials) Protection() artifact.CredentialProtection {
	return artifact.CredentialProtectionOS
}
func (store *testCredentials) Store(_ context.Context, key string, value []byte) error {
	store.mu.Lock()
	store.values[key] = append([]byte(nil), value...)
	store.mu.Unlock()
	return nil
}
func (store *testCredentials) Load(_ context.Context, key string) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.values[key]
	if !exists {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}
func (store *testCredentials) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.values[key]; !exists {
		return fs.ErrNotExist
	}
	delete(store.values, key)
	return nil
}

type testRemoteProvider struct{ remote *testRemote }

func (provider testRemoteProvider) Open(context.Context, string) (registry.Remote, error) {
	return provider.remote, nil
}

type testAuditEvent struct {
	action engine.AuditAction
	result engine.AuditResult
	digest digest.Digest
}
type testAuditTrail struct {
	mu     sync.Mutex
	events []testAuditEvent
}

func (trail *testAuditTrail) Started(_ context.Context, _ artifact.UUID, action engine.AuditAction, value digest.Digest) error {
	trail.mu.Lock()
	trail.events = append(trail.events, testAuditEvent{action: action, result: engine.AuditResultStarted, digest: value})
	trail.mu.Unlock()
	return nil
}
func (trail *testAuditTrail) Finished(_ context.Context, _ artifact.UUID, action engine.AuditAction, value digest.Digest, result engine.AuditResult) error {
	trail.mu.Lock()
	trail.events = append(trail.events, testAuditEvent{action: action, result: result, digest: value})
	trail.mu.Unlock()
	return nil
}

type testAuditFactory struct {
	mu     sync.Mutex
	trails []*testAuditTrail
}

func (factory *testAuditFactory) Open(context.Context, artifact.UUID, string, *cas.Store, *artifact.DeviceIdentity, artifact.CredentialStore, string, bool) (engine.AuditTrail, io.Closer, error) {
	trail := &testAuditTrail{}
	factory.mu.Lock()
	factory.trails = append(factory.trails, trail)
	factory.mu.Unlock()
	return trail, nopCloser{}, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type testTransactionalOutput struct {
	bytes.Buffer
	committed bool
	aborted   bool
}

func (output *testTransactionalOutput) Commit() error { output.committed = true; return nil }
func (output *testTransactionalOutput) Abort() error  { output.aborted = true; return nil }

type testOutputTarget struct{ output *testTransactionalOutput }

func (target testOutputTarget) Open(context.Context) (host.Output, error) { return target.output, nil }

type testStoredObject struct {
	descriptor artifact.Descriptor
	data       []byte
}
type testRemote struct {
	mu              sync.Mutex
	objects         map[digest.Digest]testStoredObject
	refs            []registry.AnnouncementRef
	publishFailures int
}

func newTestRemote() *testRemote { return &testRemote{objects: map[digest.Digest]testStoredObject{}} }
func (remote *testRemote) Push(ctx context.Context, expected artifact.Descriptor, source io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := io.ReadAll(source)
	if err != nil {
		return err
	}
	if digest.FromBytes(data) != expected.Digest || int64(len(data)) != expected.Size {
		return errors.New("descriptor mismatch")
	}
	remote.mu.Lock()
	remote.objects[expected.Digest] = testStoredObject{descriptor: expected, data: append([]byte(nil), data...)}
	remote.mu.Unlock()
	return nil
}
func (remote *testRemote) Open(ctx context.Context, value digest.Digest) (io.ReadCloser, artifact.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, artifact.Descriptor{}, err
	}
	remote.mu.Lock()
	object, exists := remote.objects[value]
	remote.mu.Unlock()
	if !exists {
		return nil, artifact.Descriptor{}, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(object.data)), object.descriptor, nil
}
func (remote *testRemote) Has(ctx context.Context, value digest.Digest) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	remote.mu.Lock()
	_, exists := remote.objects[value]
	remote.mu.Unlock()
	return exists, nil
}
func (remote *testRemote) PublishAnnouncement(_ context.Context, tag string, descriptor artifact.Descriptor, _ []artifact.Descriptor) error {
	remote.mu.Lock()
	if remote.publishFailures > 0 {
		remote.publishFailures--
		remote.mu.Unlock()
		return errors.New("injected announcement failure")
	}
	remote.refs = append(remote.refs, registry.AnnouncementRef{Tag: tag, Descriptor: descriptor})
	remote.mu.Unlock()
	return nil
}
func (remote *testRemote) ListAnnouncements(_ context.Context, cursor string, limit int, _ *registry.VerificationBudget) (registry.AnnouncementPage, error) {
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if cursor != "" {
		return registry.AnnouncementPage{}, nil
	}
	refs := append([]registry.AnnouncementRef(nil), remote.refs...)
	if len(refs) > limit {
		return registry.AnnouncementPage{Refs: refs[:limit], Next: "next"}, nil
	}
	return registry.AnnouncementPage{Refs: refs}, nil
}

var _ host.InputSource = (*fixedInputSource)(nil)

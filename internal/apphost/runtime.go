// Package apphost composes the trusted artifact engine into immutable host
// sessions. CLI, TUI, and Desktop depend on this package rather than storage,
// cryptography, registry, policy, audit, or plugin implementations directly.
package apphost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/enbu-net/enbu/internal/engine"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/cas"
	"github.com/enbu-net/enbu/pkg/enrollment"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/platform"
	"github.com/enbu-net/enbu/pkg/plugin"
	"github.com/enbu-net/enbu/pkg/policy"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/enbu-net/enbu/pkg/workspace"
	"github.com/opencontainers/go-digest"
)

const localEnrollmentIssuer = "devices.enbu.net"

var (
	ErrAlreadyInitialized       = errors.New("apphost: workspace already initialized")
	ErrNotInitialized           = errors.New("apphost: workspace is not initialized")
	ErrInitializationIncomplete = errors.New("apphost: workspace initialization is incomplete")
	ErrStateConflict            = errors.New("apphost: conflicting workspace session")
)

// RemoteProvider resolves credentials outside workspace-controlled data and
// constructs one exact repository remote.
type RemoteProvider interface {
	Open(context.Context, string) (registry.Remote, error)
}

type AuditFactory interface {
	Open(
		context.Context,
		artifact.UUID,
		string,
		*cas.Store,
		*artifact.DeviceIdentity,
		artifact.CredentialStore,
		string,
		bool,
	) (engine.AuditTrail, io.Closer, error)
}

type Dependencies struct {
	Credentials artifact.CredentialStore
	Remotes     RemoteProvider
	Audits      AuditFactory
	Plugins     PluginResolver
	DataDir     string
}

type Runtime struct {
	credentials artifact.CredentialStore
	remotes     RemoteProvider
	audits      AuditFactory
	plugins     PluginResolver
	dataDir     string
	executor    *Executor
	host        *host.Host

	closeMu      sync.Mutex
	enrollmentMu sync.Mutex
	mu           sync.Mutex
	state        runtimeState
}

type runtimeState uint8

const (
	runtimeOpen runtimeState = iota
	runtimeClosing
	runtimeClosed
)

func New(dependencies Dependencies) (*Runtime, error) {
	if dependencies.Credentials == nil || dependencies.Credentials.Protection() != artifact.CredentialProtectionOS || dependencies.Remotes == nil || dependencies.Audits == nil {
		return nil, artifact.ErrInsecureCredentialStore
	}
	if dependencies.DataDir == "" || !filepath.IsAbs(dependencies.DataDir) || filepath.Clean(dependencies.DataDir) != dependencies.DataDir {
		return nil, errors.New("apphost: data directory must be absolute and clean")
	}
	if err := platform.EnsurePrivateDir(dependencies.DataDir); err != nil {
		return nil, err
	}
	executor := newExecutor()
	pluginHost, err := plugin.NewHost(plugin.DefaultLimits())
	if err != nil {
		return nil, err
	}
	executor.plugins = dependencies.Plugins
	executor.pluginHost = pluginHost
	typedHost, err := host.New(executor, executor)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		credentials: dependencies.Credentials,
		remotes:     dependencies.Remotes,
		audits:      dependencies.Audits,
		plugins:     dependencies.Plugins,
		dataDir:     dependencies.DataDir,
		executor:    executor,
		host:        typedHost,
	}, nil
}

type InitializeRequest struct {
	Root     string
	Registry string
	Subject  string
}

// Session exposes only the typed host workspace and safe query methods added
// by apphost. Storage and identity capabilities remain process-owned.
type Session struct {
	runtime   *Runtime
	workspace *host.Workspace
	state     *workspaceState
}

func (session *Session) Workspace() *host.Workspace {
	if session == nil {
		return nil
	}
	return session.workspace
}

// Initialize creates the shared v1 configuration, stores the device assertion
// in the OS keychain, and starts the sole parentless initialization operation.
func (runtime *Runtime) Initialize(ctx context.Context, request InitializeRequest) (*Session, host.OperationID, error) {
	if err := runtime.validateContext(ctx); err != nil {
		return nil, "", err
	}
	root, err := validateRoot(request.Root)
	if err != nil {
		return nil, "", err
	}
	storedConfig, storedRevision, loadErr := workspace.Load(root)
	if loadErr == nil {
		if request.Registry != "" && request.Registry != storedConfig.Registry {
			return nil, "", errors.New("apphost: initialization registry does not match durable workspace state")
		}
		device, err := artifact.LoadDeviceIdentity(ctx, runtime.credentials)
		if err != nil {
			return nil, "", err
		}
		assertion, err := runtime.loadEnrollment(ctx, storedConfig.Workspace)
		if err != nil {
			return nil, "", err
		}
		state, err := runtime.prepareState(ctx, root, storedConfig, storedRevision, device, assertion, false)
		if err != nil {
			return nil, "", err
		}
		if request.Subject != "" && request.Subject != state.author.Subject() {
			return nil, "", errors.New("apphost: initialization subject does not match durable enrollment")
		}
		discovery, err := runtime.executor.discover(ctx, state)
		if err != nil {
			return nil, "", err
		}
		if len(discovery.Announcements) != 0 || len(discovery.Inaccessible) != 0 {
			return nil, "", ErrAlreadyInitialized
		}
		return runtime.startInitialization(ctx, state, assertion)
	}
	if !errors.Is(loadErr, workspace.ErrConfigNotFound) {
		return nil, "", loadErr
	}

	device, err := runtime.loadOrCreateDevice(ctx)
	if err != nil {
		return nil, "", err
	}
	authority, err := enrollment.NewAuthority(localEnrollmentIssuer, device.SigningPublicKey())
	if err != nil {
		return nil, "", err
	}
	assertion, err := enrollment.SignWithSigner(enrollment.Claims{
		Issuer:           localEnrollmentIssuer,
		DeviceID:         device.DeviceID(),
		Subject:          request.Subject,
		X25519Recipient:  device.RecipientString(),
		Ed25519PublicKey: device.SigningPublicKey(),
	}, device)
	if err != nil {
		return nil, "", err
	}
	workspaceID, err := newUUID()
	if err != nil {
		return nil, "", err
	}
	config := workspace.Config{
		APIVersion:  workspace.APIVersion,
		Kind:        workspace.KindWorkspace,
		Workspace:   workspaceID,
		Registry:    request.Registry,
		Authorities: []enrollment.Authority{authority},
	}
	revision, err := workspace.SaveNew(root, config)
	if err != nil {
		return nil, "", err
	}
	configPath, _ := workspace.ConfigPath(root)
	rollbackConfig := true
	defer func() {
		if rollbackConfig {
			_ = os.Remove(configPath)
		}
	}()
	if err := runtime.storeEnrollment(ctx, workspaceID, assertion); err != nil {
		return nil, "", err
	}
	rollbackEnrollment := true
	defer func() {
		if rollbackEnrollment {
			_ = runtime.credentials.Delete(context.WithoutCancel(ctx), enrollmentCredentialKey(workspaceID))
		}
	}()

	state, err := runtime.prepareState(ctx, root, config, revision, device, assertion, true)
	if err != nil {
		return nil, "", err
	}
	session, operation, err := runtime.startInitialization(ctx, state, assertion)
	if err != nil {
		return nil, "", err
	}
	rollbackConfig = false
	rollbackEnrollment = false
	return session, operation, nil
}

func (runtime *Runtime) startInitialization(
	ctx context.Context,
	state *workspaceState,
	assertion []byte,
) (*Session, host.OperationID, error) {
	session, err := runtime.openSession(ctx, state)
	if err != nil {
		return nil, "", err
	}
	policySource, err := session.workspace.RegisterInput(ctx, &fixedInputSource{data: policy.OwnerOnlyPolicy()})
	if err != nil {
		_ = session.Close(context.WithoutCancel(ctx))
		return nil, "", err
	}
	rootUID, err := newUUID()
	if err != nil {
		_ = session.Close(context.WithoutCancel(ctx))
		return nil, "", err
	}
	policyUID, err := newUUID()
	if err != nil {
		_ = session.Close(context.WithoutCancel(ctx))
		return nil, "", err
	}
	rootSchema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/Workspace")
	policySchema, _ := artifact.ParseTypeRef("schemas.enbu.net/v1alpha1/RegoPolicy")
	operation, err := session.workspace.Start(ctx, host.InitializeAction{
		OwnerEnrollment: digest.FromBytes(assertion),
		Root: host.DraftResource{
			Kind: artifact.KindCollection, UID: rootUID, Schema: rootSchema,
			Metadata: artifact.Metadata{Name: "workspace"},
		},
		Policy: host.DraftResource{
			Kind: artifact.KindResource, UID: policyUID, Schema: policySchema,
			Metadata: artifact.Metadata{Name: "owner-policy"},
			Payloads: []host.StagedPayload{{Name: "policy.rego", MediaType: "text/plain", Source: policySource}},
		},
	})
	if err != nil {
		_ = session.Close(context.WithoutCancel(ctx))
		return nil, "", err
	}
	return session, operation, nil
}

func (runtime *Runtime) Open(ctx context.Context, root string) (*Session, error) {
	if err := runtime.validateContext(ctx); err != nil {
		return nil, err
	}
	root, err := validateRoot(root)
	if err != nil {
		return nil, err
	}
	config, revision, err := workspace.Load(root)
	if errors.Is(err, workspace.ErrConfigNotFound) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	device, err := artifact.LoadDeviceIdentity(ctx, runtime.credentials)
	if err != nil {
		return nil, err
	}
	assertion, err := runtime.loadEnrollment(ctx, config.Workspace)
	if err != nil {
		return nil, err
	}
	state, err := runtime.prepareState(ctx, root, config, revision, device, assertion, false)
	if err != nil {
		return nil, err
	}
	dag, err := runtime.executor.completeDAG(ctx, state)
	if err != nil {
		return nil, err
	}
	if dag == nil {
		return nil, ErrInitializationIncomplete
	}
	return runtime.openSession(ctx, state)
}

func (runtime *Runtime) openSession(ctx context.Context, state *workspaceState) (*Session, error) {
	workspaceSession, err := runtime.host.OpenWorkspace(ctx, host.OpenWorkspaceRequest{
		WorkspaceID: state.config.Workspace, Root: state.root, ConfigRevision: state.revision,
	})
	if err != nil {
		return nil, err
	}
	return &Session{runtime: runtime, workspace: workspaceSession, state: state}, nil
}

func (runtime *Runtime) prepareState(
	ctx context.Context,
	root string,
	config workspace.Config,
	revision digest.Digest,
	device *artifact.DeviceIdentity,
	assertion []byte,
	initialize bool,
) (*workspaceState, error) {
	verifier, err := enrollment.NewVerifier(config.Authorities)
	if err != nil {
		return nil, err
	}
	author, err := artifact.VerifyEnrollment(ctx, verifier, assertion)
	if err != nil {
		return nil, err
	}
	if author.DeviceID() != device.DeviceID() || author.RecipientString() != device.RecipientString() || !bytes.Equal(author.SigningPublicKey(), device.SigningPublicKey()) {
		return nil, errors.New("apphost: enrollment does not bind the local device")
	}
	knownEnrollments, err := runtime.loadApprovedEnrollments(ctx, config.Workspace, verifier)
	if err != nil {
		return nil, err
	}
	knownEnrollments[author.AssertionDigest()] = author
	stateDir := filepath.Join(runtime.dataDir, "workspaces", string(config.Workspace))
	if err := platform.EnsurePrivateDir(stateDir); err != nil {
		return nil, err
	}
	objects, err := cas.New(filepath.Join(stateDir, "cas"))
	if err != nil {
		return nil, err
	}
	remote, err := runtime.remotes.Open(ctx, config.Registry)
	if err != nil {
		_ = objects.Close()
		return nil, err
	}
	auditTrail, auditCloser, err := runtime.audits.Open(ctx, config.Workspace, stateDir, objects, device, runtime.credentials, author.Subject(), initialize)
	if err != nil {
		_ = objects.Close()
		return nil, err
	}
	state := &workspaceState{
		root: root, stateDir: stateDir, config: config, revision: revision, objects: objects, remote: remote,
		device: device, author: author, verifier: verifier, audit: auditTrail,
		auditCloser: auditCloser, knownEnrollments: knownEnrollments,
	}
	registered, err := runtime.executor.register(state)
	if err != nil {
		_ = auditCloser.Close()
		_ = objects.Close()
		return nil, err
	}
	if registered != state {
		_ = auditCloser.Close()
		_ = objects.Close()
		return registered, nil
	}
	return state, nil
}

func (session *Session) Close(ctx context.Context) error {
	if session == nil || session.workspace == nil {
		return nil
	}
	err := session.workspace.Close(ctx)
	if err == nil {
		session.workspace = nil
	}
	return err
}

func (runtime *Runtime) Close(ctx context.Context) error {
	if runtime == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("apphost: nil close context")
	}
	runtime.closeMu.Lock()
	defer runtime.closeMu.Unlock()
	runtime.mu.Lock()
	if runtime.state == runtimeClosed {
		runtime.mu.Unlock()
		return nil
	}
	runtime.state = runtimeClosing
	runtime.mu.Unlock()
	if err := runtime.host.Close(ctx); err != nil {
		return err
	}
	if err := runtime.executor.close(ctx); err != nil {
		return err
	}
	runtime.mu.Lock()
	runtime.state = runtimeClosed
	runtime.mu.Unlock()
	return nil
}

func (runtime *Runtime) validateContext(ctx context.Context) error {
	if ctx == nil {
		return errors.New("apphost: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.mu.Lock()
	state := runtime.state
	runtime.mu.Unlock()
	if state != runtimeOpen {
		return errors.New("apphost: runtime is closing or closed")
	}
	return nil
}

func (runtime *Runtime) loadOrCreateDevice(ctx context.Context) (*artifact.DeviceIdentity, error) {
	device, err := artifact.LoadDeviceIdentity(ctx, runtime.credentials)
	if err == nil {
		return device, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	device, err = artifact.GenerateDeviceIdentity()
	if err != nil {
		return nil, err
	}
	if err := artifact.SaveDeviceIdentity(ctx, runtime.credentials, device); err != nil {
		return nil, err
	}
	return device, nil
}

func (runtime *Runtime) storeEnrollment(ctx context.Context, workspaceID artifact.UUID, assertion []byte) error {
	if len(assertion) == 0 || len(assertion) > artifact.MaxEnrollmentAssertionBytes {
		return errors.New("apphost: invalid enrollment assertion size")
	}
	return runtime.credentials.Store(ctx, enrollmentCredentialKey(workspaceID), append([]byte(nil), assertion...))
}

func (runtime *Runtime) loadEnrollment(ctx context.Context, workspaceID artifact.UUID) ([]byte, error) {
	assertion, err := runtime.credentials.Load(ctx, enrollmentCredentialKey(workspaceID))
	if err != nil {
		return nil, fmt.Errorf("load workspace enrollment: %w", err)
	}
	if len(assertion) == 0 || len(assertion) > artifact.MaxEnrollmentAssertionBytes {
		return nil, errors.New("apphost: invalid stored enrollment assertion")
	}
	return assertion, nil
}

func enrollmentCredentialKey(workspaceID artifact.UUID) string {
	return "workspace-enrollment-v1-" + digest.FromString(string(workspaceID)).Encoded()
}

func validateRoot(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", errors.New("apphost: workspace root must be absolute and clean")
	}
	info, err := os.Lstat(value)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("apphost: workspace root must be a real directory")
	}
	return value, nil
}

type fixedInputSource struct{ data []byte }

func (source *fixedInputSource) Open(ctx context.Context) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), source.data...))), nil
}

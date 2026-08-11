// Package desktop exposes the finite, payload-free Wails application boundary.
package desktop

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/enbu-net/enbu/internal/apphost"
	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/opencontainers/go-digest"
)

var ErrUnknownSession = errors.New("desktop: unknown workspace session")
var ErrPickerCanceled = errors.New("desktop: native file picker was canceled")

type RuntimeFactory func(context.Context) (*apphost.Runtime, apphost.ProductionIdentity, error)
type DirectoryPicker func(context.Context) (string, error)
type FilePicker func(context.Context, string) (string, error)
type SavePicker func(context.Context, string) (string, error)

type OpenWorkspaceResult struct {
	SessionID string                 `json:"session_id"`
	Snapshot  host.WorkspaceSnapshot `json:"snapshot"`
}

type InitializeWorkspaceResult struct {
	SessionID   string           `json:"session_id"`
	OperationID host.OperationID `json:"operation_id"`
}

type Service struct {
	mu       sync.Mutex
	ctx      context.Context
	runtime  *apphost.Runtime
	identity apphost.ProductionIdentity
	sessions map[string]*apphost.Session
	factory  RuntimeFactory
	picker   DirectoryPicker
	file     FilePicker
	save     SavePicker
	version  string
}

func NewService(version string) *Service {
	return &Service{
		factory:  apphost.NewProduction,
		sessions: make(map[string]*apphost.Session),
		version:  version,
	}
}

func (service *Service) SetRuntimeFactory(factory RuntimeFactory)  { service.factory = factory }
func (service *Service) SetDirectoryPicker(picker DirectoryPicker) { service.picker = picker }
func (service *Service) SetFilePicker(picker FilePicker)           { service.file = picker }
func (service *Service) SetSavePicker(picker SavePicker)           { service.save = picker }

func (service *Service) Startup(ctx context.Context) {
	service.mu.Lock()
	service.ctx = ctx
	service.mu.Unlock()
}

func (service *Service) Context() context.Context {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.ctx == nil {
		return context.Background()
	}
	return service.ctx
}

func (service *Service) ensureRuntime(ctx context.Context) (*apphost.Runtime, apphost.ProductionIdentity, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.runtime != nil {
		return service.runtime, service.identity, nil
	}
	if service.factory == nil {
		return nil, apphost.ProductionIdentity{}, errors.New("desktop: runtime factory is unavailable")
	}
	runtime, identity, err := service.factory(ctx)
	if err != nil {
		return nil, apphost.ProductionIdentity{}, err
	}
	service.runtime, service.identity = runtime, identity
	return runtime, identity, nil
}

func (service *Service) BrowseWorkspace() (OpenWorkspaceResult, error) {
	service.mu.Lock()
	picker := service.picker
	service.mu.Unlock()
	if picker == nil {
		return OpenWorkspaceResult{}, errors.New("desktop: native directory picker is unavailable")
	}
	path, err := picker(service.Context())
	if err != nil || path == "" {
		return OpenWorkspaceResult{}, err
	}
	return service.OpenWorkspace(path)
}

func (service *Service) OpenWorkspace(path string) (OpenWorkspaceResult, error) {
	ctx := service.Context()
	runtime, _, err := service.ensureRuntime(ctx)
	if err != nil {
		return OpenWorkspaceResult{}, err
	}
	session, err := runtime.Open(ctx, path)
	if err != nil {
		return OpenWorkspaceResult{}, err
	}
	snapshot, err := session.Workspace().Snapshot(ctx)
	if err != nil {
		_ = session.Close(context.WithoutCancel(ctx))
		return OpenWorkspaceResult{}, err
	}
	id := string(session.Workspace().ID())
	service.mu.Lock()
	service.sessions[id] = session
	service.mu.Unlock()
	return OpenWorkspaceResult{SessionID: id, Snapshot: snapshot}, nil
}

func (service *Service) InitializeWorkspace(path, registry string) (InitializeWorkspaceResult, error) {
	ctx := service.Context()
	runtime, identity, err := service.ensureRuntime(ctx)
	if err != nil {
		return InitializeWorkspaceResult{}, err
	}
	session, operation, err := runtime.Initialize(ctx, apphost.InitializeRequest{
		Root: path, Registry: registry, Subject: identity.Subject,
	})
	if err != nil {
		return InitializeWorkspaceResult{}, err
	}
	id := string(session.Workspace().ID())
	service.mu.Lock()
	service.sessions[id] = session
	service.mu.Unlock()
	return InitializeWorkspaceResult{SessionID: id, OperationID: operation}, nil
}

func (service *Service) Snapshot(sessionID string) (host.WorkspaceSnapshot, error) {
	session, err := service.session(sessionID)
	if err != nil {
		return host.WorkspaceSnapshot{}, err
	}
	return session.Workspace().Snapshot(service.Context())
}

func (service *Service) ListResources(sessionID, commitID, cursor string) (host.ResourcePage, error) {
	session, err := service.session(sessionID)
	if err != nil {
		return host.ResourcePage{}, err
	}
	commit, err := digest.Parse(commitID)
	if err != nil {
		return host.ResourcePage{}, err
	}
	return session.Workspace().ListResources(service.Context(), host.ListResourcesRequest{
		AtCommit: commit, Cursor: host.QueryCursor(cursor), PageSize: host.MaxQueryPageSize,
	})
}

func (service *Service) ListCommits(sessionID string, frontierValues []string, cursor string) (host.CommitPage, error) {
	session, err := service.session(sessionID)
	if err != nil {
		return host.CommitPage{}, err
	}
	frontier := make([]digest.Digest, 0, len(frontierValues))
	for _, value := range frontierValues {
		parsed, err := digest.Parse(value)
		if err != nil {
			return host.CommitPage{}, err
		}
		frontier = append(frontier, parsed)
	}
	return session.Workspace().ListCommits(service.Context(), host.ListCommitsRequest{
		Frontier: frontier, Cursor: host.QueryCursor(cursor), PageSize: host.MaxQueryPageSize,
	})
}

// StartImportFile opens a native picker and passes the resulting path directly
// into a host-owned input capability. The webview never receives or supplies a
// native path or payload bytes.
func (service *Service) StartImportFile(sessionID, name, format, mediaType string) (host.OperationID, error) {
	session, err := service.session(sessionID)
	if err != nil {
		return "", err
	}
	transformKind, payloadName, payloadMediaType, err := importFormat(format, mediaType)
	if err != nil {
		return "", err
	}
	service.mu.Lock()
	picker := service.file
	service.mu.Unlock()
	if picker == nil {
		return "", errors.New("desktop: native file picker is unavailable")
	}
	ctx := service.Context()
	path, err := picker(ctx, "Select artifact input")
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", ErrPickerCanceled
	}
	snapshot, root, err := workspaceRoot(ctx, session)
	if err != nil {
		return "", err
	}
	source, err := host.NewFileInput(path)
	if err != nil {
		return "", err
	}
	input, err := session.Workspace().RegisterInput(ctx, source)
	if err != nil {
		return "", err
	}
	uid, edgeID, err := randomPair()
	if err != nil {
		return "", err
	}
	transform, err := artifact.ParseTypeRef("transforms.enbu.net/v1alpha1/" + transformKind)
	if err != nil {
		return "", err
	}
	return session.Workspace().Start(ctx, host.TransformAction{
		BaseCommit: snapshot.Frontier[0],
		Transform:  host.TransformRef{Builtin: transform},
		Parameters: []host.TransformParameter{{Name: "input", Source: input}},
		Outputs: []host.TransformOutput{{
			Slot: "input", UID: uid, Metadata: artifact.Metadata{Name: name},
			Parent: root.UID, ExpectedParent: root.Sealed, EdgeID: edgeID,
			EdgeName: name, Relation: artifact.MemberRelation(),
			Payloads: []host.TransformPayload{{Name: payloadName, MediaType: payloadMediaType}},
		}},
	})
}

// StartMaterialize opens a native save dialog and registers a transactional
// secure output. Only identifiers and a named-stream selector cross Wails.
func (service *Service) StartMaterialize(sessionID, commitID, resourceID, payload, format string) (host.OperationID, error) {
	session, err := service.session(sessionID)
	if err != nil {
		return "", err
	}
	commit, err := digest.Parse(commitID)
	if err != nil {
		return "", err
	}
	target, err := artifact.ParseUUID(resourceID)
	if err != nil {
		return "", err
	}
	formatRef, err := artifact.ParseTypeRef("materializers.enbu.net/v1alpha1/" + format)
	if err != nil {
		return "", err
	}
	service.mu.Lock()
	picker := service.save
	service.mu.Unlock()
	if picker == nil {
		return "", errors.New("desktop: native save picker is unavailable")
	}
	ctx := service.Context()
	path, err := picker(ctx, "Save materialized artifact")
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", ErrPickerCanceled
	}
	output, err := host.NewSecureFileOutput(path)
	if err != nil {
		return "", err
	}
	destination, err := session.Workspace().RegisterOutput(ctx, output)
	if err != nil {
		return "", err
	}
	return session.Workspace().Start(ctx, host.MaterializeAction{
		AtCommit: commit, Target: target, Format: formatRef,
		Payload: payload, Destination: destination,
	})
}

func (service *Service) PollOperation(sessionID, operationID string, cursor uint64) (host.OperationSnapshot, error) {
	session, err := service.session(sessionID)
	if err != nil {
		return host.OperationSnapshot{}, err
	}
	return session.Workspace().Poll(service.Context(), host.OperationID(operationID), cursor)
}

func (service *Service) CancelOperation(sessionID, operationID string) error {
	session, err := service.session(sessionID)
	if err != nil {
		return err
	}
	return session.Workspace().Cancel(service.Context(), host.OperationID(operationID))
}

func (service *Service) CloseWorkspace(sessionID string) error {
	service.mu.Lock()
	session, exists := service.sessions[sessionID]
	service.mu.Unlock()
	if !exists {
		return ErrUnknownSession
	}
	if err := session.Close(service.Context()); err != nil {
		return err
	}
	service.mu.Lock()
	delete(service.sessions, sessionID)
	service.mu.Unlock()
	return nil
}

func (service *Service) GetAppVersion() string { return service.version }

func (service *Service) Shutdown(ctx context.Context) error {
	service.mu.Lock()
	runtime := service.runtime
	service.mu.Unlock()
	if runtime == nil {
		return nil
	}
	return runtime.Close(ctx)
}

func (service *Service) session(id string) (*apphost.Session, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	session, exists := service.sessions[id]
	if !exists {
		return nil, ErrUnknownSession
	}
	return session, nil
}

func importFormat(format, mediaType string) (string, string, string, error) {
	switch format {
	case "opaque":
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
		return "OpaqueImport", "content", mediaType, nil
	case "dotenv":
		return "DotEnvImport", "secrets.env", "text/plain", nil
	case "csv":
		return "CSVImport", "table.csv", "text/csv", nil
	case "json":
		return "JSONImport", "value.json", "application/json", nil
	default:
		return "", "", "", errors.New("desktop: unsupported import format")
	}
}

func workspaceRoot(ctx context.Context, session *apphost.Session) (host.WorkspaceSnapshot, host.ResourceMetadata, error) {
	snapshot, err := session.Workspace().Snapshot(ctx)
	if err != nil {
		return host.WorkspaceSnapshot{}, host.ResourceMetadata{}, err
	}
	if len(snapshot.Frontier) != 1 {
		return host.WorkspaceSnapshot{}, host.ResourceMetadata{}, errors.New("desktop: workspace frontier is not singular")
	}
	var cursor host.QueryCursor
	for {
		page, err := session.Workspace().ListResources(ctx, host.ListResourcesRequest{
			AtCommit: snapshot.Frontier[0], Cursor: cursor, PageSize: host.MaxQueryPageSize,
		})
		if err != nil {
			return host.WorkspaceSnapshot{}, host.ResourceMetadata{}, err
		}
		for _, resource := range page.Resources {
			if resource.Kind == artifact.KindCollection {
				return snapshot, resource, nil
			}
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	return host.WorkspaceSnapshot{}, host.ResourceMetadata{}, errors.New("desktop: workspace root is unavailable")
}

func randomPair() (artifact.UUID, artifact.UUID, error) {
	first, err := randomUUID()
	if err != nil {
		return "", "", err
	}
	second, err := randomUUID()
	return first, second, err
}

func randomUUID() (artifact.UUID, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return artifact.ParseUUID(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]))
}

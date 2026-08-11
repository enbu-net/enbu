// Package host is the in-process application boundary shared by CLI, TUI,
// and Wails. A Session is immutable after opening; every operation receives an
// explicit session and context.
package host

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/enbu-net/enbu/pkg/artifact"
	"github.com/enbu-net/enbu/pkg/platform"
	"github.com/enbu-net/enbu/pkg/registry"
)

const MaxProgressMessage = 256

var (
	ErrInvalidSession    = errors.New("host: invalid session")
	ErrInvalidAction     = errors.New("host: invalid action")
	ErrUnsupportedFormat = errors.New("host: unsupported legacy format")
)

type SessionOptions struct {
	WorkspaceID    artifact.UUID
	Root           string
	Remote         registry.Remote
	Source         artifact.ObjectSource
	Sink           artifact.ObjectSink
	ConfigRevision string
}

type sessionState struct {
	workspaceID artifact.UUID
	root        string
	remote      registry.Remote
	source      artifact.ObjectSource
	sink        artifact.ObjectSink
	config      string
}

// Session has no exported mutable fields. It is safe to copy and may be used
// concurrently for immutable reads.
type Session struct{ state *sessionState }

func (session Session) WorkspaceID() artifact.UUID {
	if session.state == nil {
		return ""
	}
	return session.state.workspaceID
}
func (session Session) Root() string {
	if session.state == nil {
		return ""
	}
	return session.state.root
}
func (session Session) ConfigRevision() string {
	if session.state == nil {
		return ""
	}
	return session.state.config
}
func (session Session) Remote() registry.Remote {
	if session.state == nil {
		return nil
	}
	return session.state.remote
}
func (session Session) Source() artifact.ObjectSource {
	if session.state == nil {
		return nil
	}
	return session.state.source
}
func (session Session) Sink() artifact.ObjectSink {
	if session.state == nil {
		return nil
	}
	return session.state.sink
}

type Host struct {
	mu       sync.RWMutex
	sessions map[*sessionState]struct{}
}

func New() *Host { return &Host{sessions: make(map[*sessionState]struct{})} }

func (host *Host) OpenSession(ctx context.Context, options SessionOptions) (Session, error) {
	if ctx == nil {
		return Session{}, fmt.Errorf("%w: nil context", ErrInvalidSession)
	}
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	if err := options.WorkspaceID.Validate(); err != nil {
		return Session{}, fmt.Errorf("%w: workspace ID: %v", ErrInvalidSession, err)
	}
	if options.Root == "" || !filepath.IsAbs(options.Root) || filepath.Clean(options.Root) != options.Root || strings.ContainsRune(options.Root, 0) {
		return Session{}, fmt.Errorf("%w: root must be absolute and clean", ErrInvalidSession)
	}
	if err := rejectLegacyConfiguration(options.Root); err != nil {
		return Session{}, err
	}
	if options.Remote == nil || options.Source == nil || options.Sink == nil {
		return Session{}, fmt.Errorf("%w: missing storage/remote", ErrInvalidSession)
	}
	if err := platform.EnsurePrivateDir(options.Root); err != nil {
		return Session{}, err
	}
	state := &sessionState{workspaceID: options.WorkspaceID, root: options.Root, remote: options.Remote, source: options.Source, sink: options.Sink, config: options.ConfigRevision}
	host.mu.Lock()
	host.sessions[state] = struct{}{}
	host.mu.Unlock()
	return Session{state: state}, nil
}

func rejectLegacyConfiguration(root string) error {
	for _, name := range []string{"enbu.toml", ".enbu.local"} {
		_, err := os.Lstat(filepath.Join(root, name))
		switch {
		case err == nil:
			return fmt.Errorf("%w: %s", ErrUnsupportedFormat, name)
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return fmt.Errorf("%w: inspect %s: %v", ErrInvalidSession, name, err)
		}
	}
	return nil
}

func (host *Host) CloseSession(session Session) error {
	if session.state == nil {
		return ErrInvalidSession
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if _, ok := host.sessions[session.state]; !ok {
		return ErrInvalidSession
	}
	delete(host.sessions, session.state)
	return nil
}

type Progress struct {
	OperationID artifact.UUID
	Sequence    uint64
	Phase       string
	Message     string
}

type Result struct {
	OperationID artifact.UUID
	Err         error
}

type Operation struct {
	ID       artifact.UUID
	Progress <-chan Progress
	Done     <-chan Result
}

type Reporter struct {
	id       artifact.UUID
	sequence uint64
	output   chan<- Progress
}

func (reporter *Reporter) Report(phase, message string) error {
	if reporter == nil || reporter.output == nil {
		return ErrInvalidAction
	}
	if phase == "" || len(phase) > MaxProgressMessage || len(message) > MaxProgressMessage || strings.ContainsRune(phase, 0) || strings.ContainsRune(message, 0) {
		return ErrInvalidAction
	}
	reporter.sequence++
	event := Progress{OperationID: reporter.id, Sequence: reporter.sequence, Phase: phase, Message: message}
	select {
	case reporter.output <- event:
		return nil
	default:
		return nil
	}
}

type Action func(context.Context, *Reporter) error

func (host *Host) Start(ctx context.Context, session Session, action string, run Action) (Operation, error) {
	if ctx == nil || session.state == nil || run == nil || action == "" || len(action) > MaxProgressMessage || strings.ContainsRune(action, 0) {
		return Operation{}, ErrInvalidAction
	}
	host.mu.RLock()
	_, registered := host.sessions[session.state]
	host.mu.RUnlock()
	if !registered {
		return Operation{}, ErrInvalidSession
	}
	id, err := newUUID()
	if err != nil {
		return Operation{}, err
	}
	progress := make(chan Progress, 32)
	done := make(chan Result, 1)
	go func() {
		defer close(progress)
		reporter := &Reporter{id: id, output: progress}
		_ = reporter.Report("started", action)
		err := run(ctx, reporter)
		phase := "succeeded"
		if err != nil {
			phase = "failed"
		}
		_ = reporter.Report(phase, "")
		done <- Result{OperationID: id, Err: err}
		close(done)
	}()
	return Operation{ID: id, Progress: progress, Done: done}, nil
}

func newUUID() (artifact.UUID, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	hexValue := hex.EncodeToString(raw)
	return artifact.ParseUUID(hexValue[:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:])
}

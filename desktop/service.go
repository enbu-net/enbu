package desktop

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/clock"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
)

// The shell supplies native dialogs, the OS browser and events to the
// frontend, so this package stays independent of the GUI toolkit.
type (
	DirectoryPicker func(context.Context) (string, error)
	BrowserOpener   func(string) error
	EventEmitter    func(name string, data any)
)

// Events the frontend can subscribe to.
const (
	EventProgress        = "enbu:progress"
	EventProgressMessage = "enbu:progress_message"
	EventConflictRetry   = "enbu:conflict_retry"
)

// ConflictRetry reports that a publish found new heads and starts over.
type ConflictRetry struct {
	Attempt     int `json:"attempt"`
	MaxAttempts int `json:"max_attempts"`
}

// Service is everything the frontend can call: the desktop app binds its
// exported methods, and desktop/rpc serves the same methods to editor
// extensions. Every exported method is a frontend operation, and one that
// fails returns an *Error.
type Service struct {
	clock      clock.Clock
	app        *app.App
	ctx        context.Context
	pickDir    DirectoryPicker
	openURL    BrowserOpener
	git        gitprovider.Client
	repoMu     sync.Mutex
	authMu     sync.Mutex
	repoPath   string
	sessions   map[string]*oauthSession
	authLogin  func(context.Context, auth.DevicePrompter) (*auth.StoredToken, error)
	emit       EventEmitter
	AppVersion string
}

type oauthSession struct {
	cancel    context.CancelFunc
	expiresAt time.Time
	status    OAuthStatus
}

func NewService(a *app.App) *Service {
	s := &Service{
		clock:    clock.New(),
		app:      a,
		openURL:  auth.OpenBrowser,
		git:      a.Git,
		sessions: make(map[string]*oauthSession),
	}
	if a.Runtime != nil && a.Runtime.Clock != nil {
		s.clock = a.Runtime.Clock
	}
	s.authLogin = func(ctx context.Context, prompt auth.DevicePrompter) (*auth.StoredToken, error) {
		return (auth.Client{Clock: s.clock}).Login(ctx, prompt)
	}
	if s.git == nil {
		s.git = gitprovider.NewCLIClient()
	}
	a.Events = events{s}
	s.loadSelectedRepo()
	return s
}

// Host is what the shell running a Service supplies: a native folder dialog,
// the OS browser, and delivery of events to the frontend. A nil field is a
// feature the shell lacks.
type Host struct {
	PickDirectory DirectoryPicker
	OpenURL       BrowserOpener
	Emit          EventEmitter
}

// Attach gives s the context of the shell running it and what the shell
// supplies. Operations started from the frontend are cancelled with ctx.
func Attach(ctx context.Context, s *Service, host Host) {
	s.ctx = ctx
	s.pickDir = host.PickDirectory
	s.openURL = host.OpenURL
	s.emit = host.Emit
}

// events delivers the app's progress to the frontend.
type events struct{ s *Service }

func (e events) OnProgress(msg string) {
	e.emit(EventProgressMessage, msg)
}

func (e events) OnStepProgress(step app.ProgressStep) {
	e.emit(EventProgress, step)
}

func (e events) OnConflictRetry(attempt, maxAttempts int) {
	e.emit(EventConflictRetry, ConflictRetry{Attempt: attempt, MaxAttempts: maxAttempts})
}

func (e events) emit(name string, data any) {
	if emit := e.s.emit; emit != nil {
		emit(name, data)
	}
}

func (s *Service) GetAppVersion() string {
	if s.AppVersion != "" {
		return s.AppVersion
	}
	return "(unset)"
}

func (s *Service) withRepo(fn func() error) error {
	_, err := withRepoResult(s, func() (struct{}, error) {
		return struct{}{}, fn()
	})
	return err
}

func withRepoResult[T any](s *Service, fn func() (T, error)) (T, error) {
	s.repoMu.Lock()
	path := s.repoPath
	s.repoMu.Unlock()
	var zero T
	if path == "" {
		return zero, publicError(errors.New("select a workspace folder first"))
	}
	v, err := withRepoPathResult(s, path, fn)
	return v, publicError(err)
}

func withRepoPathResult[T any](s *Service, path string, fn func() (T, error)) (T, error) {
	s.repoMu.Lock()
	defer s.repoMu.Unlock()
	// A queued call can outlive the RPC connection while waiting for this lock.
	if err := s.context().Err(); err != nil {
		var zero T
		return zero, err
	}
	s.app.SetRepositoryDir(path)
	return fn()
}

func (s *Service) context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

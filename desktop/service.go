package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
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
	authLogin  func(context.Context, auth.BrowserOpener) (*auth.StoredToken, error)
	accounts   accountStore
	emit       EventEmitter
	updater    AppUpdater
	updateMu   sync.Mutex
	AppVersion string
}

// accountStore holds the signed-in GitHub accounts; tests replace it.
type accountStore interface {
	Accounts() (logins []string, current string, err error)
	Switch(login string) error
	Delete(login string) error
}

// keyringAccounts is the accountStore of the OS keyring and the data directory.
type keyringAccounts struct{}

func (keyringAccounts) Accounts() ([]string, string, error) { return auth.Accounts() }
func (keyringAccounts) Switch(login string) error {
	_, err := auth.SwitchAccount(login)
	return err
}
func (keyringAccounts) Delete(login string) error { return auth.DeleteAccount(login) }

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
		accounts: keyringAccounts{},
	}
	if a.Runtime != nil && a.Runtime.Clock != nil {
		s.clock = a.Runtime.Clock
	}
	s.authLogin = func(ctx context.Context, open auth.BrowserOpener) (*auth.StoredToken, error) {
		return (auth.Client{Clock: s.clock}).Login(ctx, open)
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
	// Updater updates the desktop app; nil in an editor extension, which the
	// editor updates.
	Updater AppUpdater
}

// Attach gives s the context of the shell running it and what the shell
// supplies. Operations started from the frontend are cancelled with ctx.
func Attach(ctx context.Context, s *Service, host Host) {
	s.ctx = ctx
	s.pickDir = host.PickDirectory
	s.openURL = host.OpenURL
	s.emit = host.Emit
	s.updater = host.Updater
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

type AuthStatus struct {
	Authenticated       bool   `json:"authenticated"`
	WorkspaceConfigured bool   `json:"workspace_configured"`
	Username            string `json:"username,omitempty"`
	// Accounts are the signed-in GitHub logins, the most recent sign-in last;
	// Username is the one in use. GITHUB_TOKEN is not among them.
	Accounts []string  `json:"accounts,omitempty"`
	Repo     *RepoInfo `json:"repo,omitempty"`
}

type RepoInfo struct {
	Path              string `json:"path,omitempty"`
	Owner             string `json:"owner,omitempty"`
	Repo              string `json:"repo,omitempty"`
	Initialized       bool   `json:"initialized"`
	HasGit            bool   `json:"has_git"`
	HasRemote         bool   `json:"has_remote"`
	StorageConfigured bool   `json:"storage_configured"`
}

type OAuthStart struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OAuthStatus struct {
	State    string          `json:"state"`
	Error    *apperr.Payload `json:"error,omitempty"`
	Username string          `json:"username,omitempty"`
}

type SecretsResponse struct {
	Environment string       `json:"environment"`
	Secrets     []SecretItem `json:"secrets"`
}

type SecretItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (s *Service) GetAuthStatus() AuthStatus {
	var status AuthStatus
	s.repoMu.Lock()
	path := s.repoPath
	s.repoMu.Unlock()
	if path != "" {
		if cfg, err := config.LoadProjectFrom(path); err == nil {
			status.WorkspaceConfigured = cfg.Storage.URL != "" && !strings.HasPrefix(cfg.Storage.URL, "oci://ghcr.io/")
		}
	}
	if logins, _, err := s.accounts.Accounts(); err == nil {
		status.Accounts = logins
	}
	token, err := auth.LoadToken()
	if err != nil {
		slog.Debug("GetAuthStatus: not authenticated", "err", err)
		return status
	}
	status.Authenticated = true
	status.Username = token.Username
	if repo, err := s.GetRepoStatus(); err == nil && repo.Owner != "" {
		status.Repo = &repo
	}
	slog.Info("GetAuthStatus", "authenticated", status.Authenticated, "username", status.Username, "repo", status.Repo)
	return status
}

func (s *Service) StartOAuthLogin() (_ OAuthStart, err error) {
	defer publicInto(&err)
	slog.Info("StartOAuthLogin called")
	sessionID, err := randomSessionID()
	if err != nil {
		return OAuthStart{}, err
	}
	expiresAt := s.clock.Now().Add(10 * time.Minute)
	loginCtx, cancel := clock.WithDeadline(s.context(), s.clock, expiresAt)
	opened := make(chan struct{}, 1)
	finished := make(chan struct{})
	s.authMu.Lock()
	for _, session := range s.sessions {
		session.cancel()
	}
	s.sessions = map[string]*oauthSession{
		sessionID: {
			cancel:    cancel,
			expiresAt: expiresAt,
			status:    OAuthStatus{State: "pending"},
		},
	}
	s.authMu.Unlock()

	go func() {
		defer close(finished)
		defer cancel()
		token, err := s.authLogin(loginCtx, func(authorizeURL string) error {
			if s.openURL == nil {
				return errors.New("browser opener is unavailable")
			}
			if err := s.openURL(authorizeURL); err != nil {
				return err
			}
			opened <- struct{}{}
			return nil
		})
		if err != nil {
			slog.Error("OAuth login failed", "session_id", sessionID, "err", err)
			state := "error"
			payload := apperr.PayloadOf(err)
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				state = "expired"
				payload = apperr.PayloadOf(apperr.New(apperr.CodeAuthExpired, "login session expired", nil))
			} else if apperr.Is(err, apperr.CodeAccessDenied) {
				state = "denied"
			}
			s.setOAuthStatus(sessionID, OAuthStatus{State: state, Error: &payload})
			return
		}
		s.setOAuthStatus(sessionID, OAuthStatus{State: "success", Username: token.Username})
	}()

	select {
	case <-opened:
		return OAuthStart{SessionID: sessionID, ExpiresAt: expiresAt}, nil
	case <-finished:
		status := s.GetOAuthLoginStatus(sessionID)
		if status.State == "success" {
			return OAuthStart{SessionID: sessionID, ExpiresAt: expiresAt}, nil
		}
		if status.Error == nil {
			return OAuthStart{}, errors.New("OAuth login failed")
		}
		return OAuthStart{}, apperr.New(status.Error.Code, status.Error.Message, status.Error.Params)
	case <-s.context().Done():
		cancel()
		return OAuthStart{}, s.context().Err()
	}
}

func (s *Service) GetOAuthLoginStatus(sessionID string) OAuthStatus {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		payload := apperr.PayloadOf(apperr.New(apperr.CodeAuthExpired, "login session expired", nil))
		return OAuthStatus{State: "expired", Error: &payload}
	}
	if !s.clock.Now().Before(session.expiresAt) && session.status.State == "pending" {
		session.cancel()
		payload := apperr.PayloadOf(apperr.New(apperr.CodeAuthExpired, "login session expired", nil))
		session.status = OAuthStatus{State: "expired", Error: &payload}
	}
	return session.status
}

func (s *Service) CancelOAuthLogin(sessionID string) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	session.cancel()
	delete(s.sessions, sessionID)
}

func (s *Service) setOAuthStatus(sessionID string, status OAuthStatus) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if session, ok := s.sessions[sessionID]; ok && session.status.State == "pending" {
		if !s.clock.Now().Before(session.expiresAt) {
			payload := apperr.PayloadOf(apperr.New(apperr.CodeAuthExpired, "login session expired", nil))
			session.status = OAuthStatus{State: "expired", Error: &payload}
		} else {
			session.status = status
		}
	}
}

// Logout signs out of the GitHub account login, or of the one in use when
// login is "". Signing out of the one in use moves to the most recent
// remaining sign-in.
func (s *Service) Logout(login string) error {
	return publicError(s.accounts.Delete(login))
}

// SwitchAccount uses another signed-in GitHub account in this data directory.
func (s *Service) SwitchAccount(login string) error {
	return publicError(s.accounts.Switch(login))
}

func (s *Service) BrowseRepository() (_ RepoInfo, err error) {
	defer publicInto(&err)
	if s.pickDir == nil {
		return RepoInfo{}, fmt.Errorf("directory picker is not available")
	}
	path, err := s.pickDir(s.context())
	if err != nil {
		return RepoInfo{}, err
	}
	if path == "" {
		return RepoInfo{}, nil
	}
	return s.SelectRepository(path)
}

func (s *Service) SelectRepository(path string) (_ RepoInfo, err error) {
	defer publicInto(&err)
	repo, err := validateRepoPath(s.context(), s.git, path)
	if err != nil {
		return RepoInfo{}, apperr.Wrap(
			apperr.CodeInvalidArgument,
			"invalid repository path",
			err,
			nil,
		)
	}
	s.repoMu.Lock()
	if err := s.context().Err(); err != nil {
		s.repoMu.Unlock()
		return RepoInfo{}, err
	}
	cfg, err := config.LoadGUI()
	if err != nil {
		cfg = &config.GUIConfig{}
	}
	cfg.SelectedRepo = repo.Path
	cfg.RepoHistory = appendUnique(cfg.RepoHistory, repo.Path)
	saveErr := config.SaveGUI(cfg)
	if saveErr == nil {
		s.repoPath = repo.Path
		s.app.SetRepositoryDir(repo.Path)
	}
	s.repoMu.Unlock()
	if saveErr != nil {
		return RepoInfo{}, saveErr
	}
	return s.repoInfo(repo)
}

func (s *Service) ListRepositories() (_ []RepoInfo, err error) {
	defer publicInto(&err)
	cfg, err := config.LoadGUI()
	if err != nil {
		return nil, err
	}
	var repos []RepoInfo
	seen := make(map[string]struct{}, len(cfg.RepoHistory))
	for _, path := range cfg.RepoHistory {
		key := repoPathKey(path)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		repo, err := validateRepoPath(s.context(), s.git, path)
		if err != nil {
			continue
		}
		info, err := s.repoInfo(repo)
		if err != nil {
			continue
		}
		repos = append(repos, info)
	}
	return repos, nil
}

func (s *Service) RemoveRepository(path string) (err error) {
	defer publicInto(&err)
	s.repoMu.Lock()
	defer s.repoMu.Unlock()
	if err := s.context().Err(); err != nil {
		return err
	}
	cfg, err := config.LoadGUI()
	if err != nil {
		return err
	}
	targetKey := repoPathKey(path)
	filtered := cfg.RepoHistory[:0]
	for _, p := range cfg.RepoHistory {
		if repoPathKey(p) != targetKey {
			filtered = append(filtered, p)
		}
	}
	cfg.RepoHistory = filtered
	if cfg.SelectedRepo != "" && repoPathKey(cfg.SelectedRepo) == targetKey {
		cfg.SelectedRepo = ""
		s.repoPath = ""
	}
	return config.SaveGUI(cfg)
}

func (s *Service) ListMembers() ([]app.MemberInfo, error) {
	return withRepoResult(s, func() ([]app.MemberInfo, error) { return s.app.ListMembers(s.context()) })
}

func (s *Service) ListJoinRequests() ([]app.JoinRequestInfo, error) {
	return withRepoResult(s, func() ([]app.JoinRequestInfo, error) { return s.app.ListJoinRequests(s.context()) })
}

// ApproveMember is called after the admin has compared the device's
// fingerprint with the person who owns it.
func (s *Service) ApproveMember(deviceID string) error {
	return s.withRepo(func() error { return s.app.ApproveMember(s.context(), deviceID) })
}

func (s *Service) RemoveMember(deviceID string) error {
	return s.withRepo(func() error { return s.app.RemoveMember(s.context(), deviceID) })
}

// SetAdmin grants or revokes the right to manage members. Granting it is as
// sensitive as approving a device, so the frontend confirms the fingerprint.
func (s *Service) SetAdmin(deviceID string, admin bool) error {
	return s.withRepo(func() error { return s.app.SetAdmin(s.context(), deviceID, admin) })
}

func (s *Service) ReadConfig() (string, error) {
	return withRepoResult(s, func() (string, error) {
		return s.app.ReadConfig()
	})
}

func (s *Service) WriteConfig(content string) error {
	return s.withRepo(func() error { return s.app.WriteConfig(content) })
}

func appendUnique(slice []string, val string) []string {
	seen := make(map[string]struct{}, len(slice)+1)
	result := slice[:0]
	for _, existing := range slice {
		key := repoPathKey(existing)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, existing)
	}
	key := repoPathKey(val)
	if _, exists := seen[key]; exists {
		return result
	}
	return append(result, val)
}

// repoPathKey compares two spellings of a repository path. Windows matches
// names in any letter case, also for a folder that no longer exists.
func repoPathKey(path string) string {
	key := fsutil.Canonical(path)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}

func (s *Service) GetRepoStatus() (_ RepoInfo, err error) {
	defer publicInto(&err)
	s.repoMu.Lock()
	path := s.repoPath
	s.repoMu.Unlock()
	if path == "" {
		return RepoInfo{}, nil
	}
	repo, err := validateRepoPath(s.context(), s.git, path)
	if err != nil {
		return RepoInfo{}, err
	}
	return s.repoInfo(repo)
}

// SuggestStorage is the storage Initialize founds a workspace in when given
// none: a GHCR repository beside the GitHub origin, as `enbu init` picks.
func (s *Service) SuggestStorage() (string, error) {
	return withRepoResult(s, func() (string, error) { return s.app.DefaultStorageURL() })
}

// Initialize sets this device up in the selected repository, as `enbu init`
// does. It founds a workspace in storage, or in SuggestStorage's when
// storage.URL is empty; with an enbu.toml that names a storage it joins that
// workspace, and storage.URL must be empty. acceptNewGenesis is
// `--accept-new-genesis`.
func (s *Service) Initialize(storage config.StorageConfig, acceptNewGenesis bool) (app.InitResult, error) {
	return withRepoResult(s, func() (app.InitResult, error) {
		opts := app.InitOptions{AcceptNewGenesis: acceptNewGenesis}
		if storage.URL != "" {
			if cfg, err := config.LoadProjectFrom(s.app.RepositoryDir); err == nil && cfg.Storage.URL != "" {
				return app.InitResult{}, apperr.New(apperr.CodeInvalidArgument, "enbu.toml already names the storage", nil)
			}
			opts.Storage = &storage
		}
		result, err := s.app.InitializeRepository(s.context(), opts)
		if err != nil {
			return app.InitResult{}, err
		}
		for _, warning := range result.Warnings {
			slog.Warn("initialize", "warning", warning)
		}
		return *result, nil
	})
}

func (s *Service) ListEnvironments() ([]app.EnvInfo, error) {
	return withRepoResult(s, s.app.ListEnvironments)
}

func (s *Service) CreateEnvironment(name string) error {
	return s.withRepo(func() error { return s.app.CreateEnvironment(name) })
}

func (s *Service) SwitchEnvironment(name string) error {
	return s.withRepo(func() error { return s.app.SwitchEnvironment(name) })
}

func (s *Service) RenameEnvironment(name, newName string) error {
	return s.withRepo(func() error { return s.app.RenameEnvironment(name, newName) })
}

// DeleteEnvironment removes an environment from enbu.toml. With purge its
// stored revisions are deleted too (admin only); without, they stay and the
// result names the incarnation PurgeIncarnation deletes them by later.
func (s *Service) DeleteEnvironment(name string, purge bool) (app.EnvironmentDeletion, error) {
	return withRepoResult(s, func() (app.EnvironmentDeletion, error) {
		return s.app.DeleteEnvironment(s.context(), name, purge)
	})
}

// PurgeIncarnation deletes the stored revisions of an environment deleted
// without purging them (admin only), and returns how many it deleted.
func (s *Service) PurgeIncarnation(incarnation string) (int, error) {
	return withRepoResult(s, func() (int, error) {
		return s.app.PurgeIncarnation(s.context(), incarnation)
	})
}

func (s *Service) ListSecrets(env string) (SecretsResponse, error) {
	return withRepoResult(s, func() (SecretsResponse, error) {
		secrets, err := s.app.ListSecrets(s.context(), env)
		if err != nil {
			return SecretsResponse{}, err
		}
		currentEnv, _ := s.app.CurrentEnvironment()
		if env == "" {
			env = currentEnv
		}
		keys := make([]string, 0, len(secrets))
		for key := range secrets {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		items := make([]SecretItem, 0, len(keys))
		for _, key := range keys {
			items = append(items, SecretItem{Key: key, Value: secrets[key]})
		}
		return SecretsResponse{Environment: env, Secrets: items}, nil
	})
}

func (s *Service) AddSecret(env, key, value string) error {
	return s.withRepo(func() error { return s.app.AddSecret(s.context(), env, key, value) })
}

func (s *Service) EditSecret(env, key, value string) error {
	return s.withRepo(func() error { return s.app.EditSecret(s.context(), env, key, value) })
}

func (s *Service) DeleteSecret(env, key string) error {
	return s.withRepo(func() error { return s.app.DeleteSecret(s.context(), env, key) })
}

// PullSecrets writes the environment's secrets to its output file. With replace
// the file's current content is dropped, including a file enbu cannot read
// (output_unreadable), which a pull otherwise refuses to overwrite.
func (s *Service) PullSecrets(env string, replace bool) (app.WrittenFile, error) {
	return withRepoResult(s, func() (app.WrittenFile, error) {
		written, err := s.app.PullSecretsToFileWith(s.context(), env, replace)
		if err != nil {
			return app.WrittenFile{}, err
		}
		return *written, nil
	})
}

func (s *Service) SyncSecrets(env string) error {
	return s.withRepo(func() error { return s.app.SyncSecrets(s.context(), env) })
}

func (s *Service) ListConflicts(env string) (app.ConflictSet, error) {
	return withRepoResult(s, func() (app.ConflictSet, error) {
		set, err := s.app.ListConflicts(s.context(), env)
		if err != nil {
			return app.ConflictSet{}, err
		}
		return *set, nil
	})
}

// ResolveConflicts publishes a decision for every conflicted key. heads are the
// ConflictSet.Heads the person decided from; if anyone wrote since, nothing is
// published and the call fails with CodeConflict.
func (s *Service) ResolveConflicts(env string, heads []string, choices []app.SecretChoice) error {
	return s.withRepo(func() error { return s.app.ResolveSecrets(s.context(), env, heads, choices) })
}

func (s *Service) ListHistory(env string) ([]app.HistoryEntry, error) {
	return withRepoResult(s, func() ([]app.HistoryEntry, error) { return s.app.ListHistory(s.context(), env) })
}

func (s *Service) DiffHistory(env string, from, to int) (app.Diff, error) {
	return withRepoResult(s, func() (app.Diff, error) {
		diff, err := s.app.DiffHistory(s.context(), env, from, to)
		if err != nil {
			return app.Diff{}, err
		}
		return *diff, nil
	})
}

func (s *Service) RestoreHistory(env string, index int) error {
	return s.withRepo(func() error { return s.app.RestoreHistory(s.context(), env, index) })
}

func (s *Service) GetAppVersion() string {
	if s.AppVersion != "" {
		return s.AppVersion
	}
	return "(unset)"
}

func (s *Service) loadSelectedRepo() {
	cfg, err := config.LoadGUI()
	if err != nil || cfg.SelectedRepo == "" {
		return
	}
	repo, err := validateRepoPath(s.context(), s.git, cfg.SelectedRepo)
	if err != nil {
		return
	}
	s.repoPath = repo.Path
	s.app.SetRepositoryDir(repo.Path)
}

func (s *Service) repoInfo(repo *SelectedRepo) (RepoInfo, error) {
	info := RepoInfo{
		Path:      repo.Path,
		Owner:     repo.Owner,
		Repo:      repo.Repo,
		HasGit:    repo.HasGit,
		HasRemote: repo.HasRemote,
	}
	return withRepoPathResult(s, repo.Path, func() (RepoInfo, error) {
		if cfg, err := config.LoadProjectFrom(repo.Path); err == nil {
			info.StorageConfigured = cfg.Storage.URL != ""
			_, identityErr := s.app.IdentityInfo()
			info.Initialized = identityErr == nil
		}
		return info, nil
	})
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

func randomSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating login session ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

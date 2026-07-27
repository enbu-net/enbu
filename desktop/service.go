package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/auth"
	"github.com/enbu-net/enbu/config"
	gitprovider "github.com/enbu-net/enbu/provider/git"
	gh "github.com/enbu-net/enbu/provider/github"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type DirectoryPicker func(context.Context) (string, error)
type BrowserOpener func(string) error

type repositoryPlatform interface {
	ListRepositoryOwners(context.Context) ([]gh.RepositoryOwner, error)
	CreateRepository(context.Context, string, string, bool) (*gh.CreateRepoResult, error)
}

type Service struct {
	app        *app.App
	ctx        context.Context
	pickDir    DirectoryPicker
	openURL    BrowserOpener
	git        gitprovider.Client
	github     func(string) repositoryPlatform
	repoMu     sync.Mutex
	authMu     sync.Mutex
	repoPath   string
	sessions   map[string]*oauthSession
	authLogin  func(context.Context, auth.BrowserOpener) (*auth.StoredToken, error)
	emitEvent  func(context.Context, string, ...interface{})
	AppVersion string
}

type oauthSession struct {
	cancel    context.CancelFunc
	expiresAt time.Time
	status    OAuthStatus
}

func NewService(a *app.App) *Service {
	s := &Service{
		app:     a,
		openURL: auth.OpenBrowser,
		git:     a.Git,
		github: func(token string) repositoryPlatform {
			return gh.NewClient(token)
		},
		sessions:  make(map[string]*oauthSession),
		authLogin: auth.Login,
		emitEvent: wailsruntime.EventsEmit,
	}
	if s.git == nil {
		s.git = gitprovider.NewCLIClient()
	}
	a.Events = s
	s.loadSelectedRepo()
	return s
}

func (s *Service) OnProgress(msg string) {
	if s.ctx != nil {
		s.emitEvent(s.ctx, "enbu:progress_message", msg)
	}
}

func (s *Service) OnStepProgress(step app.ProgressStep) {
	if s.ctx != nil {
		s.emitEvent(s.ctx, "enbu:progress", step)
	}
}

func (s *Service) OnConflictRetry(attempt, maxAttempts int) {
	if s.ctx != nil {
		s.emitEvent(s.ctx, "enbu:conflict_retry", map[string]int{
			"attempt":      attempt,
			"max_attempts": maxAttempts,
		})
	}
}

func (s *Service) Startup(ctx context.Context) {
	slog.Info("Service.Startup called")
	s.ctx = ctx
}

func (s *Service) Context() context.Context {
	return s.ctx
}

func (s *Service) SetDirectoryPicker(picker DirectoryPicker) {
	s.pickDir = picker
}

func (s *Service) SetBrowserOpener(opener BrowserOpener) {
	s.openURL = opener
}

type AuthStatus struct {
	Authenticated bool      `json:"authenticated"`
	Username      string    `json:"username,omitempty"`
	Repo          *RepoInfo `json:"repo,omitempty"`
}

type RepoInfo struct {
	Path        string `json:"path,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Repo        string `json:"repo,omitempty"`
	Initialized bool   `json:"initialized"`
	HasGit      bool   `json:"has_git"`
	HasRemote   bool   `json:"has_remote"`
}

type OAuthStart struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type OAuthStatus struct {
	State    string `json:"state"`
	Message  string `json:"message,omitempty"`
	Username string `json:"username,omitempty"`
}

type Environment struct {
	Name    string `json:"name"`
	Current bool   `json:"current"`
}

type SecretsResponse struct {
	Environment string       `json:"environment"`
	Cached      bool         `json:"cached"`
	Secrets     []SecretItem `json:"secrets"`
}

type SecretItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type HistoryEntry struct {
	Index     int       `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Tag       string    `json:"tag"`
}

type Recipient struct {
	Username    string `json:"username"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
}

func (s *Service) GetAuthStatus() (AuthStatus, error) {
	var status AuthStatus
	token, err := auth.LoadToken()
	if err != nil {
		slog.Debug("GetAuthStatus: not authenticated", "err", err)
		return status, nil
	}
	status.Authenticated = true
	status.Username = token.Username
	if repo, err := s.GetRepoStatus(); err == nil && repo.Owner != "" {
		status.Repo = &repo
	}
	slog.Info("GetAuthStatus", "authenticated", status.Authenticated, "username", status.Username, "repo", status.Repo)
	return status, nil
}

func (s *Service) StartOAuthLogin() (OAuthStart, error) {
	slog.Info("StartOAuthLogin called")
	sessionID, err := randomSessionID()
	if err != nil {
		return OAuthStart{}, err
	}
	expiresAt := time.Now().Add(10 * time.Minute)
	loginCtx, cancel := context.WithDeadline(s.context(), expiresAt)
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
			state := "error"
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				state = "expired"
			} else if errors.Is(err, auth.ErrAccessDenied) {
				state = "denied"
			}
			s.setOAuthStatus(sessionID, OAuthStatus{State: state, Message: err.Error()})
			return
		}
		s.setOAuthStatus(sessionID, OAuthStatus{State: "success", Username: token.Username})
	}()

	select {
	case <-opened:
		return OAuthStart{SessionID: sessionID, ExpiresAt: expiresAt}, nil
	case <-finished:
		status, _ := s.GetOAuthLoginStatus(sessionID)
		if status.State == "success" {
			return OAuthStart{SessionID: sessionID, ExpiresAt: expiresAt}, nil
		}
		if status.Message == "" {
			status.Message = "OAuth login failed"
		}
		return OAuthStart{}, errors.New(status.Message)
	case <-s.context().Done():
		cancel()
		return OAuthStart{}, s.context().Err()
	}
}

func (s *Service) GetOAuthLoginStatus(sessionID string) (OAuthStatus, error) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return OAuthStatus{State: "expired", Message: "login session expired"}, nil
	}
	if time.Now().After(session.expiresAt) && session.status.State == "pending" {
		session.status = OAuthStatus{State: "expired", Message: "login session expired"}
	}
	return session.status, nil
}

func (s *Service) CancelOAuthLogin(sessionID string) error {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}
	session.cancel()
	delete(s.sessions, sessionID)
	return nil
}

func (s *Service) setOAuthStatus(sessionID string, status OAuthStatus) {
	s.authMu.Lock()
	defer s.authMu.Unlock()
	if session, ok := s.sessions[sessionID]; ok {
		session.status = status
	}
}

func (s *Service) Logout() error {
	return auth.DeleteToken()
}

func (s *Service) BrowseRepository() (RepoInfo, error) {
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

func (s *Service) SelectRepository(path string) (RepoInfo, error) {
	repo, err := validateRepoPath(s.context(), s.git, path)
	if err != nil {
		return RepoInfo{}, err
	}
	s.repoMu.Lock()
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

func (s *Service) ListRepositories() ([]RepoInfo, error) {
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

func (s *Service) RemoveRepository(path string) error {
	s.repoMu.Lock()
	defer s.repoMu.Unlock()
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

// GitInit runs `git init` in the given path and re-selects it.
func (s *Service) GitInit(path string) (RepoInfo, error) {
	if err := s.git.Init(s.context(), path); err != nil {
		return RepoInfo{}, err
	}
	return s.SelectRepository(path)
}

func (s *Service) ListRepositoryOwners() ([]gh.RepositoryOwner, error) {
	token, err := auth.LoadToken()
	if err != nil {
		return nil, fmt.Errorf("not authenticated: %w", err)
	}
	return s.github(token.AccessToken).ListRepositoryOwners(s.context())
}

// GitCreateRemote creates a GitHub repository and sets it as origin, then re-selects.
func (s *Service) GitCreateRemote(path, owner, repoName string, private bool) (RepoInfo, error) {
	token, err := auth.LoadToken()
	if err != nil {
		return RepoInfo{}, fmt.Errorf("not authenticated: %w", err)
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return RepoInfo{}, fmt.Errorf("repository owner is required")
	}
	organization := owner
	if strings.EqualFold(owner, token.Username) {
		organization = ""
	}
	client := s.github(token.AccessToken)
	result, err := client.CreateRepository(s.context(), organization, repoName, private)
	if err != nil {
		return RepoInfo{}, err
	}
	if err := s.git.AddRemote(s.context(), path, "origin", preferredRemoteURL(result)); err != nil {
		return RepoInfo{}, fmt.Errorf("git remote add: %w", err)
	}
	return s.SelectRepository(path)
}

func preferredRemoteURL(result *gh.CreateRepoResult) string {
	return result.HTTPSURL
}

func (s *Service) ListRecipients() ([]Recipient, error) {
	return withRepoResult(s, func() ([]Recipient, error) {
		infos, err := s.app.ListRecipients(s.context())
		if err != nil {
			return nil, err
		}
		out := make([]Recipient, len(infos))
		for i, r := range infos {
			out[i] = Recipient{
				Username:    r.Username,
				Fingerprint: r.Fingerprint,
				PublicKey:   r.PublicKey,
			}
		}
		return out, nil
	})
}

func (s *Service) ReadConfig() (string, error) {
	return withRepoResult(s, func() (string, error) {
		return s.app.ReadConfig()
	})
}

func (s *Service) WriteConfig(content string) error {
	return s.withRepo(func() error {
		cfg, err := config.ParseProject(content)
		if err != nil {
			return err
		}
		if err := config.ValidateProjectOutputs(cfg); err != nil {
			return err
		}
		if err := ensureGitignore(s.app.RepositoryDir, projectGitignoreEntries(cfg)...); err != nil {
			return fmt.Errorf("updating .gitignore: %w", err)
		}
		return s.app.WriteConfig(content)
	})
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

func repoPathKey(path string) string {
	key := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}

func (s *Service) GetRepoStatus() (RepoInfo, error) {
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

func (s *Service) Initialize() (map[string]any, error) {
	return withRepoResult(s, func() (map[string]any, error) {
		result, err := s.app.InitializeRepository(s.context())
		if err != nil {
			return nil, err
		}
		if err := ensureGitignore(s.app.RepositoryDir); err != nil {
			slog.Warn("failed to update .gitignore", "err", err)
		}
		return map[string]any{
			"public_key":  result.PublicKey,
			"username":    result.Username,
			"environment": result.Environment,
		}, nil
	})
}

func (s *Service) ListEnvironments() ([]Environment, error) {
	return withRepoResult(s, func() ([]Environment, error) {
		envs, err := s.app.ListEnvironments()
		if err != nil {
			return nil, err
		}
		items := make([]Environment, len(envs))
		for i, env := range envs {
			items[i] = Environment{Name: env.Name, Current: env.IsCurrent}
		}
		return items, nil
	})
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

func (s *Service) DeleteEnvironment(name string) error {
	return s.withRepo(func() error { return s.app.DeleteEnvironment(name) })
}

func (s *Service) ListSecrets(env string) (SecretsResponse, error) {
	return withRepoResult(s, func() (SecretsResponse, error) {
		secrets, cached, err := s.app.ListSecretsWithCacheState(s.context(), env)
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
		return SecretsResponse{Environment: env, Cached: cached, Secrets: items}, nil
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

func (s *Service) PullSecrets(env string) error {
	return s.withRepo(func() error {
		_, _, err := s.app.PullSecrets(s.context(), env)
		return err
	})
}

func (s *Service) ExportSecrets(env string) error {
	return s.withRepo(func() error {
		_, err := s.app.ExportSecretsToFile(s.context(), env)
		return err
	})
}

func (s *Service) SyncSecrets(env string) error {
	return s.withRepo(func() error { return s.app.SyncSecrets(s.context(), env) })
}

func (s *Service) ListHistory(env string) ([]HistoryEntry, error) {
	return withRepoResult(s, func() ([]HistoryEntry, error) {
		entries, err := s.app.ListHistory(s.context(), env)
		if err != nil {
			return nil, err
		}
		out := make([]HistoryEntry, len(entries))
		for i, entry := range entries {
			out[i] = HistoryEntry{Index: entry.Index, Timestamp: entry.Timestamp, Tag: entry.Tag}
		}
		return out, nil
	})
}

func (s *Service) DiffHistory(env string, from, to int) (*app.Diff, error) {
	return withRepoResult(s, func() (*app.Diff, error) {
		return s.app.DiffHistory(s.context(), env, from, to)
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
		if _, err := config.LoadProjectFrom(repo.Path); err == nil {
			identities, identityErr := app.LoadIdentitiesForRepo(s.app.KeyStore, repo.Owner, repo.Repo)
			info.Initialized = identityErr == nil && len(identities) > 0
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
		return zero, fmt.Errorf("select a Git repository first")
	}
	return withRepoPathResult(s, path, fn)
}

func withRepoPathResult[T any](s *Service, path string, fn func() (T, error)) (T, error) {
	s.repoMu.Lock()
	defer s.repoMu.Unlock()
	s.app.SetRepositoryDir(path)
	return fn()
}

func (s *Service) context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

var desktopGitignoreEntries = []string{
	".env",
	".env.*",
	"!.env.example",
	".enbu.local",
}

func projectGitignoreEntries(cfg *config.ProjectConfig) []string {
	var entries []string
	for _, name := range cfg.EnvironmentNames() {
		env, err := cfg.Environment(name)
		if err != nil {
			continue
		}
		output := strings.TrimSpace(env.Output)
		if output == "" || filepath.IsAbs(output) {
			continue
		}
		if strings.HasPrefix(output, "#") || strings.HasPrefix(output, "!") {
			output = `\` + output
		}
		entries = append(entries, output)
	}
	return entries
}

func ensureGitignore(repoRoot string, extraEntries ...string) error {
	path := filepath.Join(repoRoot, ".gitignore")
	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}
	lines := strings.Split(existing, "\n")
	lineSet := make(map[string]bool)
	for _, l := range lines {
		lineSet[strings.TrimSpace(l)] = true
	}
	var toAdd []string
	entries := append([]string{}, desktopGitignoreEntries...)
	entries = append(entries, extraEntries...)
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry != "" && !lineSet[entry] {
			toAdd = append(toAdd, entry)
			lineSet[entry] = true
		}
	}
	if len(toAdd) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	_, err = f.WriteString("\n# enbu - exclude .env files\n" + strings.Join(toAdd, "\n") + "\n")
	return err
}

func randomSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating login session ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

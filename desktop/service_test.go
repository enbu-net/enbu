package desktop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/internal/application"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/config"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
	gh "github.com/enbu-net/enbu/pkg/provider/github"
)

type fakeRepositoryPlatform struct {
	owners       []gh.RepositoryOwner
	organization string
}

func (f *fakeRepositoryPlatform) ListRepositoryOwners(context.Context) ([]gh.RepositoryOwner, error) {
	return f.owners, nil
}

func (f *fakeRepositoryPlatform) CreateRepository(
	_ context.Context,
	organization string,
	name string,
	_ bool,
) (*gh.CreateRepoResult, error) {
	f.organization = organization
	owner := organization
	if owner == "" {
		owner = "octo"
	}
	return &gh.CreateRepoResult{
		Owner:    owner,
		Name:     name,
		SSHURL:   "git@github.com:" + owner + "/" + name + ".git",
		HTTPSURL: "https://github.com/" + owner + "/" + name + ".git",
	}, nil
}

type fakeServiceGit struct {
	hasRemote bool
	remote    string
}

func (f *fakeServiceGit) Inspect(_ context.Context, path string) (gitprovider.Repository, error) {
	return gitprovider.Repository{
		Root:      path,
		OriginURL: f.remote,
		HasGit:    true,
		HasRemote: f.hasRemote,
	}, nil
}

func (*fakeServiceGit) Init(context.Context, string) error { return nil }

func (f *fakeServiceGit) AddRemote(_ context.Context, _, _, url string) error {
	f.hasRemote = true
	f.remote = url
	return nil
}

func (*fakeServiceGit) CommitFiles(context.Context, string, []string, string) error { return nil }

type desktopKeyStore struct{ values map[string][]byte }

func (s *desktopKeyStore) Store(_, key string, value []byte) error {
	s.values[key] = value
	return nil
}

func (s *desktopKeyStore) Load(_, key string) ([]byte, error) {
	value, ok := s.values[key]
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return value, nil
}

func TestValidateRepoPath(t *testing.T) {
	repoDir := newGitRepo(t)

	repo, err := ValidateRepoPath(repoDir)
	if err != nil {
		t.Fatalf("ValidateRepoPath: %v", err)
	}
	if repo.Path != repoDir {
		t.Fatalf("Path = %q, want %q", repo.Path, repoDir)
	}
	if repo.Owner != "octo" || repo.Repo != "hello" {
		t.Fatalf("repo = %s/%s, want octo/hello", repo.Owner, repo.Repo)
	}
}

func TestOnStepProgressEmitsWailsEvent(t *testing.T) {
	s := NewService(app.New())
	s.ctx = context.Background()
	var eventName string
	var payload []interface{}
	s.emitEvent = func(_ context.Context, name string, data ...interface{}) {
		eventName = name
		payload = data
	}
	want := app.ProgressStep{Op: "pull", Step: "decrypt", Status: "done"}
	s.OnStepProgress(want)
	if eventName != "enbu:progress" {
		t.Fatalf("event name = %q", eventName)
	}
	if len(payload) != 1 || !reflect.DeepEqual(payload[0], want) {
		t.Fatalf("payload = %#v, want %#v", payload, want)
	}
}

func TestValidateRepoPathRejectsMissingPath(t *testing.T) {
	if _, err := ValidateRepoPath(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("ValidateRepoPath succeeded for missing path")
	}
}

func TestSelectRepositoryClassifiesInvalidPaths(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(filePath, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	paths := []string{"", filepath.Join(t.TempDir(), "missing"), filePath}
	for _, path := range paths {
		s := NewService(app.New())
		s.ctx = context.Background()
		if _, err := s.SelectRepository(path); !apperr.Is(err, apperr.CodeInvalidArgument) {
			t.Errorf("SelectRepository(%q) error = %v, want %q", path, err, apperr.CodeInvalidArgument)
		}
	}
}

func TestGitInitInitializesSelectedDirectory(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	s := NewService(app.New())
	s.ctx = context.Background()

	repo, err := s.GitInit(dir)
	if err != nil {
		t.Fatalf("GitInit: %v", err)
	}
	if !repo.HasGit {
		t.Fatal("GitInit returned HasGit=false")
	}
	if repo.HasRemote {
		t.Fatal("GitInit returned HasRemote=true without origin")
	}
	if repo.Path != runGit(t, dir, "rev-parse", "--show-toplevel") {
		t.Fatalf("repo path = %q, want initialized directory", repo.Path)
	}
}

func TestListRepositoryOwners(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GITHUB_ACTOR", "octo")
	want := []gh.RepositoryOwner{
		{Login: "octo"},
		{Login: "octo-org", Organization: true},
	}
	platform := &fakeRepositoryPlatform{owners: want}
	s := NewService(app.New())
	s.github = func(token string) repositoryPlatform {
		if token != "test-token" {
			t.Fatalf("token = %q", token)
		}
		return platform
	}

	owners, err := s.ListRepositoryOwners()
	if err != nil {
		t.Fatalf("ListRepositoryOwners: %v", err)
	}
	if !reflect.DeepEqual(owners, want) {
		t.Fatalf("owners = %#v, want %#v", owners, want)
	}
}

func TestGitCreateRemoteSelectsPersonalOrOrganizationOwner(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GITHUB_ACTOR", "octo")

	tests := []struct {
		name             string
		owner            string
		wantOrganization string
	}{
		{name: "personal account", owner: "octo", wantOrganization: ""},
		{name: "organization", owner: "octo-org", wantOrganization: "octo-org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gitClient := &fakeServiceGit{}
			platform := &fakeRepositoryPlatform{}
			a := app.New()
			a.Git = gitClient
			s := NewService(a)
			s.github = func(string) repositoryPlatform { return platform }

			repo, err := s.GitCreateRemote(t.TempDir(), tt.owner, "example", true)
			if err != nil {
				t.Fatalf("GitCreateRemote: %v", err)
			}
			if platform.organization != tt.wantOrganization {
				t.Fatalf("organization = %q, want %q", platform.organization, tt.wantOrganization)
			}
			if repo.Owner != tt.owner || !repo.HasRemote {
				t.Fatalf("repo = %#v", repo)
			}
		})
	}
}

func TestStartOAuthLogin(t *testing.T) {
	a := app.New()
	a.KeyStore = &desktopKeyStore{values: make(map[string][]byte)}
	s := NewService(a)
	s.ctx = context.Background()
	s.SetBrowserOpener(func(url string) error {
		if url != "https://github.com/login/oauth/authorize" {
			t.Fatalf("opened url = %q", url)
		}
		return nil
	})
	cancelled := make(chan struct{})
	s.authLogin = func(ctx context.Context, open auth.BrowserOpener) (*auth.StoredToken, error) {
		if err := open("https://github.com/login/oauth/authorize"); err != nil {
			return nil, err
		}
		<-ctx.Done()
		close(cancelled)
		return nil, context.Canceled
	}

	start, err := s.StartOAuthLogin()
	if err != nil {
		t.Fatalf("StartOAuthLogin: %v", err)
	}
	if start.SessionID == "" {
		t.Fatal("SessionID is empty")
	}
	if err := s.CancelOAuthLogin(start.SessionID); err != nil {
		t.Fatalf("CancelOAuthLogin: %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not reach the login context")
	}
}

func TestGetOAuthLoginStatus(t *testing.T) {
	tests := []struct {
		name      string
		status    OAuthStatus
		expiresAt time.Time
		want      string
	}{
		{name: "success", status: OAuthStatus{State: "success"}, expiresAt: time.Now().Add(time.Minute), want: "success"},
		{name: "denied", status: OAuthStatus{State: "denied"}, expiresAt: time.Now().Add(time.Minute), want: "denied"},
		{name: "error", status: OAuthStatus{State: "error"}, expiresAt: time.Now().Add(time.Minute), want: "error"},
		{name: "expired", status: OAuthStatus{State: "pending"}, expiresAt: time.Now().Add(-time.Second), want: "expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewService(app.New())
			s.sessions["session"] = &oauthSession{
				cancel:    func() {},
				expiresAt: tt.expiresAt,
				status:    tt.status,
			}
			got, err := s.GetOAuthLoginStatus("session")
			if err != nil || got.State != tt.want {
				t.Fatalf("GetOAuthLoginStatus() = %#v, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestStartOAuthLoginCancelsFailedContext(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	s := NewService(app.New())
	s.ctx = context.Background()
	var loginContext context.Context
	s.authLogin = func(ctx context.Context, _ auth.BrowserOpener) (*auth.StoredToken, error) {
		loginContext = ctx
		return nil, errors.New("login failed")
	}

	if _, err := s.StartOAuthLogin(); err == nil {
		t.Fatal("StartOAuthLogin succeeded")
	}
	select {
	case <-loginContext.Done():
	case <-time.After(time.Second):
		t.Fatal("failed login context was not cancelled")
	}
	if !strings.Contains(logs.String(), "login failed") {
		t.Fatalf("OAuth failure was not logged: %q", logs.String())
	}
}

func TestStartOAuthLoginClassifiesExpiredContext(t *testing.T) {
	s := NewService(app.New())
	s.ctx = context.Background()
	s.authLogin = func(context.Context, auth.BrowserOpener) (*auth.StoredToken, error) {
		return nil, context.DeadlineExceeded
	}

	_, err := s.StartOAuthLogin()
	if !apperr.Is(err, apperr.CodeAuthExpired) {
		t.Fatalf("StartOAuthLogin error = %v, want %q", err, apperr.CodeAuthExpired)
	}
}

func TestSelectRepositoryUpdatesHistory(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	a := app.New()
	a.KeyStore = &desktopKeyStore{values: make(map[string][]byte)}
	s := NewService(a)
	s.ctx = context.Background()

	if _, err := s.SelectRepository(repoDir); err != nil {
		t.Fatalf("SelectRepository: %v", err)
	}

	repos, err := s.ListRepositories()
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("got %d repos, want 1", len(repos))
	}
	if repos[0].Path != repoDir {
		t.Fatalf("repo path = %q, want %q", repos[0].Path, repoDir)
	}
}

func TestListRepositoriesRemovesLegacyDuplicates(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	if err := config.SaveGUI(&config.GUIConfig{
		SelectedRepo: repoDir,
		RepoHistory:  []string{repoDir, repoDir},
	}); err != nil {
		t.Fatal(err)
	}
	s := NewService(app.New())
	s.ctx = context.Background()

	repos, err := s.ListRepositories()
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("got %d repositories, want one deduplicated repository", len(repos))
	}
}

func TestRepositoryOperationsDoNotChangeWorkingDirectory(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	if err := os.WriteFile(filepath.Join(repoDir, "enbu.toml"), []byte("version = \"v1alpha1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	a := app.New()
	a.KeyStore = &desktopKeyStore{values: make(map[string][]byte)}
	s := NewService(a)
	if _, err := s.SelectRepository(repoDir); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListEnvironments(); err != nil {
		t.Fatal(err)
	}
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if current != original {
		t.Fatalf("working directory changed to %q, want %q", current, original)
	}
}

func TestRepoInfoRequiresPrivateKeyForInitialized(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	if err := os.WriteFile(filepath.Join(repoDir, "enbu.toml"), []byte("version = \"v1alpha1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	keyStore := &desktopKeyStore{values: make(map[string][]byte)}
	a := app.New()
	a.KeyStore = keyStore
	s := NewService(a)

	info, err := s.SelectRepository(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Initialized {
		t.Fatal("repository reported initialized without a private key")
	}

	identity, err := agecrypto.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyStore.values[app.RepoKeystoreKey("octo", "hello")] = []byte(identity.String())
	info, err = s.GetRepoStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !info.Initialized {
		t.Fatal("repository not initialized after private key was stored")
	}
}

func TestWriteConfigAddsCustomOutputToGitignore(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	if err := os.WriteFile(filepath.Join(repoDir, "enbu.toml"), []byte("version = \"v1alpha1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := app.New()
	a.KeyStore = &desktopKeyStore{values: make(map[string][]byte)}
	s := NewService(a)
	if _, err := s.SelectRepository(repoDir); err != nil {
		t.Fatal(err)
	}

	content := "version = \"v1alpha1\"\n[env.dev]\noutput = \"secrets.local\"\n"
	if err := s.WriteConfig(content); err != nil {
		t.Fatal(err)
	}
	gitignore, err := os.ReadFile(filepath.Join(repoDir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gitignore), "secrets.local") {
		t.Fatalf(".gitignore does not contain custom output: %q", gitignore)
	}
}

func TestWriteConfigClassifiesUserContentErrors(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	if err := os.WriteFile(filepath.Join(repoDir, "enbu.toml"), []byte("version = \"v1alpha1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := app.New()
	a.KeyStore = &desktopKeyStore{values: make(map[string][]byte)}
	s := NewService(a)
	if _, err := s.SelectRepository(repoDir); err != nil {
		t.Fatal(err)
	}

	for _, content := range []string{
		"not valid toml =",
		"version = \"v1alpha1\"\n[env.dev]\noutput = \"../outside\"\n",
	} {
		err := s.WriteConfig(content)
		if !apperr.Is(err, apperr.CodeInvalidArgument) {
			t.Fatalf("WriteConfig(%q) error = %v, want invalid_argument", content, err)
		}
	}
}

func TestPreferredRemoteURLUsesHTTPS(t *testing.T) {
	result := &gh.CreateRepoResult{SSHURL: "git@github.com:octo/hello.git", HTTPSURL: "https://github.com/octo/hello.git"}
	if got := preferredRemoteURL(result); got != result.HTTPSURL {
		t.Fatalf("preferredRemoteURL = %q, want %q", got, result.HTTPSURL)
	}
}

func TestRemoveRepository(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	s := NewService(app.New())
	s.ctx = context.Background()

	if _, err := s.SelectRepository(repoDir); err != nil {
		t.Fatalf("SelectRepository: %v", err)
	}

	if err := s.RemoveRepository(repoDir); err != nil {
		t.Fatalf("RemoveRepository: %v", err)
	}

	repos, err := s.ListRepositories()
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 0 {
		t.Fatalf("got %d repos after remove, want 0", len(repos))
	}

	cfg, err := config.LoadGUI()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SelectedRepo != "" {
		t.Fatalf("SelectedRepo = %q, want empty after removing active repo", cfg.SelectedRepo)
	}
}

func TestRemoveRepositoryMatchesNormalizedPath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	s := NewService(app.New())
	s.ctx = context.Background()
	if _, err := s.SelectRepository(repoDir); err != nil {
		t.Fatalf("SelectRepository: %v", err)
	}

	pathWithDot := repoDir + string(filepath.Separator) + "."
	if err := s.RemoveRepository(pathWithDot); err != nil {
		t.Fatalf("RemoveRepository: %v", err)
	}
	cfg, err := config.LoadGUI()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.RepoHistory) != 0 || cfg.SelectedRepo != "" {
		t.Fatalf("repository was not removed: %#v", cfg)
	}
	status, err := s.GetRepoStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Path != "" {
		t.Fatalf("selected repository remains: %#v", status)
	}
}

func newGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "remote", "add", "origin", "https://github.com/octo/hello.git")
	return runGit(t, dir, "rev-parse", "--show-toplevel")
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %s: %v", args, out, err)
	}
	return string(bytes.TrimSpace(out))
}

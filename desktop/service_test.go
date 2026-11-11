package desktop

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
)

func TestValidateRepoPath(t *testing.T) {
	repoDir := newGitRepo(t)

	repo, err := validateRepoPath(context.Background(), gitprovider.NewCLIClient(), repoDir)
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

func TestProgressEmitsEvents(t *testing.T) {
	s := NewService(app.New(clock.New()))
	// Without an emitter the hooks are no-ops.
	s.app.Events.OnStepProgress(app.ProgressStep{Op: "pull"})

	type event struct {
		name string
		data any
	}
	var events []event
	Attach(t.Context(), s, Host{Emit: func(name string, data any) {
		events = append(events, event{name, data})
	}})
	step := app.ProgressStep{Op: "pull", Step: "decrypt", Status: "done"}
	s.app.Events.OnStepProgress(step)
	s.app.Events.OnProgress("decrypting")
	s.app.Events.OnConflictRetry(2, 5)
	want := []event{
		{EventProgress, step},
		{EventProgressMessage, "decrypting"},
		{EventConflictRetry, ConflictRetry{Attempt: 2, MaxAttempts: 5}},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %#v, want %#v", events, want)
	}
}

func TestValidateRepoPathRejectsMissingPath(t *testing.T) {
	if _, err := validateRepoPath(context.Background(), gitprovider.NewCLIClient(), filepath.Join(t.TempDir(), "missing")); err == nil {
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
		s := NewService(app.New(clock.New()))
		s.ctx = context.Background()
		if _, err := s.SelectRepository(path); !apperr.Is(err, apperr.CodeInvalidArgument) {
			t.Errorf("SelectRepository(%q) error = %v, want %q", path, err, apperr.CodeInvalidArgument)
		}
	}
}

func TestStartOAuthLogin(t *testing.T) {
	a := app.New(clock.New())
	a.Identities = &apptest.Identities{}
	s := NewService(a)
	s.ctx = context.Background()
	s.openURL = (func(url string) error {
		if url != "https://github.com/login/device" {
			t.Fatalf("opened url = %q", url)
		}
		return nil
	})
	cancelled := make(chan struct{})
	s.authLogin = func(ctx context.Context, prompt auth.DevicePrompter) (*auth.StoredToken, error) {
		if err := prompt(auth.DeviceAuthorization{UserCode: "ABCD-1234", VerificationURI: "https://github.com/login/device"}); err != nil {
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
	if start.SessionID == "" || start.UserCode != "ABCD-1234" || start.VerificationURI != "https://github.com/login/device" {
		t.Fatalf("start = %+v", start)
	}
	s.CancelOAuthLogin(start.SessionID)
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
			s := NewService(app.New(clock.New()))
			s.sessions["session"] = &oauthSession{
				cancel:    func() {},
				expiresAt: tt.expiresAt,
				status:    tt.status,
			}
			if got := s.GetOAuthLoginStatus("session"); got.State != tt.want {
				t.Fatalf("GetOAuthLoginStatus() = %#v; want %q", got, tt.want)
			}
		})
	}
}

type concurrentLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *concurrentLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *concurrentLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func TestStartOAuthLoginCancelsFailedContext(t *testing.T) {
	var logs concurrentLogBuffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	s := NewService(app.New(clock.New()))
	s.ctx = context.Background()
	var loginContext context.Context
	s.authLogin = func(ctx context.Context, _ auth.DevicePrompter) (*auth.StoredToken, error) {
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
	s := NewService(app.New(clock.New()))
	s.ctx = context.Background()
	s.authLogin = func(context.Context, auth.DevicePrompter) (*auth.StoredToken, error) {
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
	a := app.New(clock.New())
	a.Identities = &apptest.Identities{}
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

func TestListRepositoriesDeduplicatesHistory(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	if err := config.SaveGUI(&config.GUIConfig{
		SelectedRepo: repoDir,
		RepoHistory:  []string{repoDir, repoDir},
	}); err != nil {
		t.Fatal(err)
	}
	s := NewService(app.New(clock.New()))
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
	if err := os.WriteFile(filepath.Join(repoDir, "enbu.toml"), []byte("version = \"v1alpha2\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	a := app.New(clock.New())
	a.Identities = &apptest.Identities{}
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
	if err := os.WriteFile(filepath.Join(repoDir, "enbu.toml"), []byte("version = \"v1alpha2\"\nworkspace_id = \"11111111-1111-4111-8111-111111111111\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	keyStore := &apptest.Identities{}
	a := app.New(clock.New())
	a.Identities = keyStore
	s := NewService(a)

	info, err := s.SelectRepository(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Initialized {
		t.Fatal("repository reported initialized without a private key")
	}

	keyStore.Use("11111111-1111-4111-8111-111111111111", nil, nil)
	info, err = s.GetRepoStatus()
	if err != nil {
		t.Fatal(err)
	}
	if !info.Initialized {
		t.Fatal("repository not initialized after private key was stored")
	}
}

func TestConfiguredStorageCanBeSelectedWithoutGitOrGitHub(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	dir := t.TempDir()
	cfg := config.NewProjectWithEnvironment("default")
	cfg.Storage = config.StorageConfig{URL: "local:///tmp/enbu-desktop-test"}
	if err := config.SaveProjectTo(dir, cfg); err != nil {
		t.Fatal(err)
	}
	s := NewService(app.New(clock.New()))
	info, err := s.SelectRepository(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.StorageConfigured || info.HasGit || info.HasRemote {
		t.Fatalf("%+v", info)
	}
	if status := s.GetAuthStatus(); !status.WorkspaceConfigured {
		t.Fatalf("%+v", status)
	}
	cfg.Storage = config.StorageConfig{URL: "oci://ghcr.io/example/workspace"}
	if err := config.SaveProjectTo(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if status := s.GetAuthStatus(); status.WorkspaceConfigured {
		t.Fatalf("GitHub auth mode bypassed login: %+v", status)
	}
}

func TestWriteConfigAddsCustomOutputToGitignore(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	if err := os.WriteFile(filepath.Join(repoDir, "enbu.toml"), []byte("version = \"v1alpha2\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := app.New(clock.New())
	a.Identities = &apptest.Identities{}
	s := NewService(a)
	if _, err := s.SelectRepository(repoDir); err != nil {
		t.Fatal(err)
	}

	content := "version = \"v1alpha2\"\n[env.dev]\noutput = \"secrets.local\"\n"
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
	if err := os.WriteFile(filepath.Join(repoDir, "enbu.toml"), []byte("version = \"v1alpha2\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := app.New(clock.New())
	a.Identities = &apptest.Identities{}
	s := NewService(a)
	if _, err := s.SelectRepository(repoDir); err != nil {
		t.Fatal(err)
	}

	for _, content := range []string{
		"not valid toml =",
		"version = \"v1alpha2\"\n[env.dev]\noutput = \"../outside\"\n",
	} {
		err := s.WriteConfig(content)
		if !apperr.Is(err, apperr.CodeInvalidArgument) {
			t.Fatalf("WriteConfig(%q) error = %v, want invalid_argument", content, err)
		}
	}
}

func TestRemoveRepository(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	repoDir := newGitRepo(t)
	s := NewService(app.New(clock.New()))
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
	s := NewService(app.New(clock.New()))
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
	// git prints forward slashes on Windows; the service gives the canonical path.
	return fsutil.Canonical(runGit(t, dir, "rev-parse", "--show-toplevel"))
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

// A repository whose path holds Japanese and spaces (and, outside Windows,
// ends in a space) is selected, remembered in gui.toml and listed again by
// the path the CLI resolves.
func TestSelectRepositoryInNonASCIIPath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", filepath.Join(t.TempDir(), "データ 置き場"))
	name := "日本語 リポジトリ (テスト)"
	if runtime.GOOS != "windows" {
		name += " "
	}
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init")
	runGit(t, dir, "remote", "add", "origin", "https://github.com/octo/hello.git")
	a := app.New(clock.New())
	a.Identities = &apptest.Identities{}
	s := NewService(a)
	s.ctx = context.Background()

	want := fsutil.Canonical(dir)
	selected, err := s.SelectRepository(filepath.Join(dir, "."))
	if err != nil || selected.Path != want || selected.Owner != "octo" {
		t.Fatalf("SelectRepository = %+v, %v, want path %q", selected, err, want)
	}
	repos, err := s.ListRepositories()
	if err != nil || len(repos) != 1 || repos[0].Path != want {
		t.Fatalf("ListRepositories = %+v, %v", repos, err)
	}
	if err := s.RemoveRepository(filepath.ToSlash(dir)); err != nil {
		t.Fatal(err)
	}
	if repos, err := s.ListRepositories(); err != nil || len(repos) != 0 {
		t.Fatalf("after removal: %+v, %v", repos, err)
	}
}

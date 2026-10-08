//go:build scenario

package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"

	enbuapp "github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/app/apptest"
	enbucli "github.com/enbu-net/enbu/cli"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/provider"
	"github.com/enbu-net/enbu/pkg/storage"
)

type testUser struct {
	svc      *enbuapp.App
	keyPair  *age.KeyPair
	name     string
	deviceID string
}

type ScenarioState struct {
	ctx         context.Context
	owner       string
	repo        string
	registryRef string
	users       map[string]*testUser
	// founder created the workspace and is its first admin. Later users join
	// and are approved by the founder.
	founder *testUser
}

type Step struct {
	name string
	run  func(t *testing.T, s *ScenarioState)
}

func StepFunc(name string, fn func(t *testing.T, s *ScenarioState)) Step {
	return Step{name: name, run: fn}
}

func RunScenario(t *testing.T, steps ...Step) {
	t.Helper()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	if err := os.Chdir(workDir); err != nil {
		t.Fatal(err)
	}

	owner, repo := uniqueRepo(t)
	cfg := config.NewProjectWithEnvironment("default")
	cfg.Storage = config.StorageConfig{URL: "oci://localhost:5000/" + owner + "/" + repo + "-enbu", PlainHTTP: true}
	if err := config.SaveProject(cfg); err != nil {
		t.Fatal(err)
	}
	state := &ScenarioState{
		ctx:         context.Background(),
		owner:       owner,
		repo:        repo,
		registryRef: fmt.Sprintf("localhost:5000/%s/%s-enbu", owner, repo),
		users:       make(map[string]*testUser),
	}

	for _, step := range steps {
		if ok := t.Run(step.name, func(t *testing.T) {
			step.run(t, state)
		}); !ok {
			t.FailNow()
		}
	}
}

func Users(names ...string) Step {
	return StepFunc(fmt.Sprintf("users %s", strings.Join(names, ", ")), func(t *testing.T, s *ScenarioState) {
		for _, name := range names {
			if _, ok := s.users[name]; ok {
				t.Fatalf("duplicate user %q", name)
			}
			s.users[name] = setupTestUser(t, s.owner, s.repo, name)
		}
	})
}

// Register makes user a member: the first user creates the workspace, and every
// later user requests to join and is approved by the founder.
func Register(user string) Step {
	return StepFunc(fmt.Sprintf("%s registers", user), func(t *testing.T, s *ScenarioState) {
		s.register(t, s.user(t, user))
	})
}

// Join makes user request to join without anyone approving it.
func Join(user string) Step {
	return StepFunc(fmt.Sprintf("%s requests to join", user), func(t *testing.T, s *ScenarioState) {
		u := s.user(t, user)
		res, err := u.svc.InitializeRepository(s.ctx)
		if err != nil {
			t.Fatalf("%s init: %v", user, err)
		}
		if !res.Pending {
			t.Fatalf("%s should be waiting for approval", user)
		}
		u.deviceID = res.DeviceID
	})
}

// Approve has admin approve user's pending join request.
func Approve(admin, user string) Step {
	return StepFunc(fmt.Sprintf("%s approves %s", admin, user), func(t *testing.T, s *ScenarioState) {
		u := s.user(t, user)
		if err := s.user(t, admin).svc.ApproveMember(s.ctx, u.deviceID); err != nil {
			t.Fatalf("%s approves %s: %v", admin, user, err)
		}
		if _, err := u.svc.InitializeRepository(s.ctx); err != nil {
			t.Fatalf("%s init after approval: %v", user, err)
		}
	})
}

// Remove has admin remove user from the workspace.
func Remove(admin, user string) Step {
	return StepFunc(fmt.Sprintf("%s removes %s", admin, user), func(t *testing.T, s *ScenarioState) {
		if err := s.user(t, admin).svc.RemoveMember(s.ctx, s.user(t, user).deviceID); err != nil {
			t.Fatalf("%s removes %s: %v", admin, user, err)
		}
	})
}

func (s *ScenarioState) register(t *testing.T, u *testUser) {
	t.Helper()
	res, err := u.svc.InitializeRepository(s.ctx)
	if err != nil {
		t.Fatalf("%s init: %v", u.name, err)
	}
	u.deviceID = res.DeviceID
	if s.founder == nil {
		if res.Pending {
			t.Fatalf("%s should have created the workspace", u.name)
		}
		s.founder = u
		return
	}
	if !res.Pending {
		return
	}
	if err := s.founder.svc.ApproveMember(s.ctx, res.DeviceID); err != nil {
		t.Fatalf("%s approves %s: %v", s.founder.name, u.name, err)
	}
	if res, err = u.svc.InitializeRepository(s.ctx); err != nil || res.Pending {
		t.Fatalf("%s init after approval: pending=%v err=%v", u.name, res != nil && res.Pending, err)
	}
}

func Add(user, key, value string) Step {
	return StepFunc(fmt.Sprintf("%s adds %s", user, key), func(t *testing.T, s *ScenarioState) {
		addSecret(t, s.ctx, s.user(t, user), key, value)
	})
}

func AddEnv(user, env, key, value string) Step {
	return StepFunc(fmt.Sprintf("%s adds %s to %s", user, key, env), func(t *testing.T, s *ScenarioState) {
		addSecretEnv(t, s.ctx, s.user(t, user), env, key, value)
	})
}

func AddFails(user, key, value string) Step {
	return StepFunc(fmt.Sprintf("%s add %s fails", user, key), func(t *testing.T, s *ScenarioState) {
		if err := addSecretExpectFail(t, s.ctx, s.user(t, user), key, value); err == nil {
			t.Fatalf("expected %s add %s to fail", user, key)
		}
	})
}

func Edit(user, key, value string) Step {
	return StepFunc(fmt.Sprintf("%s edits %s", user, key), func(t *testing.T, s *ScenarioState) {
		editSecret(t, s.ctx, s.user(t, user), key, value)
	})
}

func Delete(user, key string) Step {
	return StepFunc(fmt.Sprintf("%s deletes %s", user, key), func(t *testing.T, s *ScenarioState) {
		deleteSecret(t, s.ctx, s.user(t, user), key)
	})
}

func Sync(user string) Step {
	return StepFunc(fmt.Sprintf("%s syncs", user), func(t *testing.T, s *ScenarioState) {
		syncSecrets(t, s.ctx, s.user(t, user))
	})
}

func SyncEnv(user, env string) Step {
	return StepFunc(fmt.Sprintf("%s syncs %s", user, env), func(t *testing.T, s *ScenarioState) {
		syncSecretsEnv(t, s.ctx, s.user(t, user), env)
	})
}

func PullFails(user string) Step {
	return StepFunc(fmt.Sprintf("%s pull fails", user), func(t *testing.T, s *ScenarioState) {
		if err := pullExpectFail(t, s.ctx, s.user(t, user)); err == nil {
			t.Fatalf("expected %s pull to fail", user)
		}
	})
}

func PullFailsEnv(user, env string) Step {
	return StepFunc(fmt.Sprintf("%s pull %s fails", user, env), func(t *testing.T, s *ScenarioState) {
		if err := pullExpectFailEnv(t, s.ctx, s.user(t, user), env); err == nil {
			t.Fatalf("expected %s pull %s to fail", user, env)
		}
	})
}

func PullContains(user, expected string) Step {
	return PullContainsAll(user, expected)
}

func PullContainsAll(user string, expected ...string) Step {
	return StepFunc(fmt.Sprintf("%s pull contains %s", user, strings.Join(expected, ", ")), func(t *testing.T, s *ScenarioState) {
		output := pullStdout(t, s.ctx, s.user(t, user))
		for _, want := range expected {
			if !strings.Contains(output, want) {
				t.Fatalf("%s pull missing %q: %s", user, want, output)
			}
		}
	})
}

func PullEnvContainsAll(user, env string, expected ...string) Step {
	return StepFunc(fmt.Sprintf("%s pull %s contains %s", user, env, strings.Join(expected, ", ")), func(t *testing.T, s *ScenarioState) {
		output := pullStdoutEnv(t, s.ctx, s.user(t, user), env)
		for _, want := range expected {
			if !strings.Contains(output, want) {
				t.Fatalf("%s pull %s missing %q: %s", user, env, want, output)
			}
		}
	})
}

func PullDoesNotContain(user string, unexpected ...string) Step {
	return StepFunc(fmt.Sprintf("%s pull excludes %s", user, strings.Join(unexpected, ", ")), func(t *testing.T, s *ScenarioState) {
		output := pullStdout(t, s.ctx, s.user(t, user))
		for _, notWant := range unexpected {
			if strings.Contains(output, notWant) {
				t.Fatalf("%s pull unexpectedly contained %q: %s", user, notWant, output)
			}
		}
	})
}

func PullEnvDoesNotContain(user, env string, unexpected ...string) Step {
	return StepFunc(fmt.Sprintf("%s pull %s excludes %s", user, env, strings.Join(unexpected, ", ")), func(t *testing.T, s *ScenarioState) {
		output := pullStdoutEnv(t, s.ctx, s.user(t, user), env)
		for _, notWant := range unexpected {
			if strings.Contains(output, notWant) {
				t.Fatalf("%s pull %s unexpectedly contained %q: %s", user, env, notWant, output)
			}
		}
	})
}

func (s *ScenarioState) user(t *testing.T, name string) *testUser {
	t.Helper()
	user, ok := s.users[name]
	if !ok {
		t.Fatalf("unknown scenario user %q", name)
	}
	return user
}

func uniqueRepo(t *testing.T) (owner, repo string) {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating random bytes: %v", err)
	}
	return "test", fmt.Sprintf("%s-%s", strings.ToLower(t.Name()), hex.EncodeToString(b))
}

func setupTestUser(t *testing.T, owner, repo, username string) *testUser {
	t.Helper()

	kp, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair for %s: %v", username, err)
	}

	cfg, err := config.LoadProject()
	if err != nil {
		t.Fatalf("loading scenario workspace: %v", err)
	}
	ks := newMockKeyStore()
	if err := ks.storeSecret("enbu", cfg.WorkspaceID, []byte(kp.Identity.String())); err != nil {
		t.Fatalf("storing key for %s: %v", username, err)
	}

	st, err := storage.NewOCI("localhost:5000/"+owner+"/"+repo+"-enbu", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	svc := &enbuapp.App{
		Storage:       st,
		TokenProvider: &mockTokenProvider{accessToken: "", username: username},
		Identities:    ks,
		RepoDetector:  &mockRepoDetector{owner: owner, repo: repo},
		Platform:      &mockGitHubClient{orgs: map[string]bool{}},
	}

	return &testUser{svc: svc, keyPair: kp, name: username}
}

type mockTokenProvider struct {
	accessToken string
	username    string
}

func (m *mockTokenProvider) LoadToken() (string, string, error) {
	return m.accessToken, m.username, nil
}

type mockRepoDetector struct {
	owner string
	repo  string
}

func (m *mockRepoDetector) LoadRepo() (string, string, error) {
	return m.owner, m.repo, nil
}

type mockKeyStore struct {
	apptest.Signers
	mu   sync.RWMutex
	data map[string][]byte
}

func newMockKeyStore() *mockKeyStore {
	return &mockKeyStore{data: make(map[string][]byte)}
}

func (m *mockKeyStore) storeSecret(_, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), value...)
	return nil
}

func (m *mockKeyStore) loadSecret(_, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), d...), nil
}

type mockGitHubClient struct {
	user *provider.User
	orgs map[string]bool
}

func (m *mockGitHubClient) GetUser(_ context.Context) (*provider.User, error) {
	return m.user, nil
}

func (m *mockGitHubClient) IsOrganization(_ context.Context, login string) bool {
	return m.orgs[login]
}

func (m *mockGitHubClient) SourceRepoURL(owner, repo string) string {
	return "https://github.com/" + owner + "/" + repo
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	readErr := make(chan error, 1)
	go func() {
		_, err := buf.ReadFrom(r)
		readErr <- err
	}()

	origStdout := os.Stdout
	os.Stdout = w
	defer func() {
		os.Stdout = origStdout
		_ = w.Close()
		_ = r.Close()
	}()

	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("closing stdout pipe: %v", err)
	}

	if err := <-readErr; err != nil {
		t.Fatalf("reading stdout: %v", err)
	}
	return buf.String()
}

func pullStdout(t *testing.T, ctx context.Context, user *testUser) string {
	t.Helper()
	return captureStdout(t, func() {
		if err := executeCommand(ctx, user.svc, "pull", "--stdout"); err != nil {
			t.Fatalf("%s pull: %v", user.name, err)
		}
	})
}

func pullStdoutEnv(t *testing.T, ctx context.Context, user *testUser, env string) string {
	t.Helper()
	return captureStdout(t, func() {
		if err := executeCommand(ctx, user.svc, "pull", "--env", env, "--stdout"); err != nil {
			t.Fatalf("%s pull %s: %v", user.name, env, err)
		}
	})
}

func pullExpectFail(t *testing.T, ctx context.Context, user *testUser) error {
	t.Helper()
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()

	origStdout := os.Stdout
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
	}()

	return executeCommand(ctx, user.svc, "pull", "--stdout")
}

func pullExpectFailEnv(t *testing.T, ctx context.Context, user *testUser, env string) error {
	t.Helper()
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()

	origStdout := os.Stdout
	os.Stdout = devNull
	defer func() {
		os.Stdout = origStdout
	}()

	return executeCommand(ctx, user.svc, "pull", "--env", env, "--stdout")
}

func addSecret(t *testing.T, ctx context.Context, user *testUser, key, value string) {
	t.Helper()
	if err := executeCommand(ctx, user.svc, "add", key, value); err != nil {
		t.Fatalf("%s add %s: %v", user.name, key, err)
	}
}

func addSecretEnv(t *testing.T, ctx context.Context, user *testUser, env, key, value string) {
	t.Helper()
	if err := executeCommand(ctx, user.svc, "add", "--env", env, key, value); err != nil {
		t.Fatalf("%s add %s %s: %v", user.name, env, key, err)
	}
}

func addSecretExpectFail(t *testing.T, ctx context.Context, user *testUser, key, value string) error {
	t.Helper()
	return executeCommand(ctx, user.svc, "add", key, value)
}

func editSecret(t *testing.T, ctx context.Context, user *testUser, key, value string) {
	t.Helper()
	if err := executeCommand(ctx, user.svc, "edit", key, value); err != nil {
		t.Fatalf("%s edit %s: %v", user.name, key, err)
	}
}

func deleteSecret(t *testing.T, ctx context.Context, user *testUser, key string) {
	t.Helper()
	if err := executeCommand(ctx, user.svc, "delete", key); err != nil {
		t.Fatalf("%s delete %s: %v", user.name, key, err)
	}
}

func syncSecrets(t *testing.T, ctx context.Context, user *testUser) {
	t.Helper()
	if err := executeCommand(ctx, user.svc, "sync"); err != nil {
		t.Fatalf("%s sync: %v", user.name, err)
	}
}

func syncSecretsEnv(t *testing.T, ctx context.Context, user *testUser, env string) {
	t.Helper()
	if err := executeCommand(ctx, user.svc, "sync", "--env", env); err != nil {
		t.Fatalf("%s sync %s: %v", user.name, env, err)
	}
}

func executeCommand(ctx context.Context, svc *enbuapp.App, args ...string) error {
	cmd := enbucli.NewWithApp("test", svc)
	cmd.SetArgs(args)
	cmd.SetContext(ctx)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	return cmd.Execute()
}

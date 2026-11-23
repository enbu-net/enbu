package app

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/jonboulle/clockwork"
)

func TestExplicitNestedCheckoutDoesNotEditParent(t *testing.T) {
	parent := newAlice(t)
	nested := filepath.Join(parent.RepositoryDir, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	child := &App{RepositoryDir: nested}
	before, err := parent.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.CreateEnvironment("child"); err != nil {
		t.Fatal(err)
	}
	after, err := parent.ReadConfig()
	if err != nil || before != after {
		t.Fatalf("parent configuration changed: %v", err)
	}
	cfg, err := child.loadProject()
	if err != nil || !cfg.HasEnvironment("child") {
		t.Fatalf("child configuration was not written: %v", err)
	}
}

func TestCanceledEnvironmentDeleteKeepsConfig(t *testing.T) {
	a := newAlice(t)
	if err := a.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := a.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := a.DeleteEnvironment(ctx, "staging", false); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled delete: %v", err)
	}
	cfg, err := a.loadProject()
	if err != nil || !cfg.HasEnvironment("staging") {
		t.Fatalf("canceled delete removed staging: %v", err)
	}
}

func TestConcurrentEnvironmentCreationPreservesBothChanges(t *testing.T) {
	a := newAlice(t)
	b := *a
	a.Runtime = &Runtime{}
	started, resume := make(chan struct{}), make(chan struct{})
	var pause sync.Once
	a.Runtime.NewID = func() string {
		pause.Do(func() {
			close(started)
			<-resume
		})
		return uuid.NewV4().String()
	}
	first := make(chan error, 1)
	go func() { first <- a.CreateEnvironment("staging") }()
	select {
	case <-started:
	case err := <-first:
		t.Fatalf("first create failed before allocating an incarnation: %v", err)
	}
	// The first call is between reading and writing enbu.toml.
	requireProjectLockBusy(t, &b)
	second := make(chan error, 1)
	go func() { second <- b.CreateEnvironment("production") }()
	close(resume)
	for _, result := range []chan error{first, second} {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := a.loadProject()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HasEnvironment("production") || !cfg.HasEnvironment("staging") {
		t.Fatalf("lost a successful update: %+v", cfg.Environments)
	}
}

func TestPersonalSwitchDoesNotOpenProjectLock(t *testing.T) {
	a := newAlice(t)
	if err := a.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	lock, err := a.lockProject(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := a.SwitchEnvironment("default"); err != nil {
		t.Fatal(err)
	}
	current, err := a.CurrentEnvironment()
	if err != nil || current != "default" {
		t.Fatalf("personal selection = %q, %v", current, err)
	}
}

func TestProjectLockUsesSameFileForSymlinkedCheckout(t *testing.T) {
	a := newAlice(t)
	alias := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(a.RepositoryDir, alias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	aliasApp := *a
	aliasApp.RepositoryDir = alias
	first, err := aliasApp.lockProject(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	requireProjectLockBusy(t, a)
}

func TestConfigReservesOnlyTheNewProjectLockPath(t *testing.T) {
	a := newAlice(t)
	if err := a.CreateEnvironment("enbu-lock"); err != nil {
		t.Fatal(err)
	}
	original, err := a.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{config.ProjectLockDir, config.ProjectLockDir + "/vars.env"} {
		content := strings.Replace(original, `".env.enbu-lock"`, `"`+path+`"`, 1)
		if original == content {
			t.Fatal("fixture did not contain the default output")
		}
		if err := a.WriteConfig(content, original); !apperr.Is(err, apperr.CodeInvalidArgument) {
			t.Fatalf("using the lock path as output: %v", err)
		}
	}
}

func TestConfigSaveRejectsAnOlderDraft(t *testing.T) {
	a := newAlice(t)
	original, err := a.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteConfig(original+"\n# edited draft\n", original); !apperr.Is(err, apperr.CodeConfigChanged) {
		t.Fatalf("saving stale configuration: %v", err)
	}
	cfg, err := a.loadProject()
	if err != nil || !cfg.HasEnvironment("staging") {
		t.Fatalf("successful creation lost: %v %v", cfg, err)
	}
}

func TestReadWriteConfig(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "enbu.toml")
	want := "version = \"v1alpha2\"\ndefault_env = \"default\"\n"
	if err := os.WriteFile(tomlPath, []byte(want), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{RepositoryDir: dir}

	got, err := a.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if got != want {
		t.Fatalf("ReadConfig = %q, want %q", got, want)
	}

	newContent := "version = \"v1alpha2\"\ndefault_env = \"production\"\n"
	if err := a.WriteConfig(newContent, got); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}

	data, err := os.ReadFile(tomlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "production") {
		t.Fatalf("written config = %q, expected to contain production", string(data))
	}
}

func TestWriteConfigRejectsOutputOutsideRepository(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "enbu.toml")
	original := "version = \"v1alpha2\"\n"
	if err := os.WriteFile(tomlPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	a := &App{RepositoryDir: dir}
	err := a.WriteConfig("version = \"v1alpha2\"\n[env.dev]\noutput = \"../secrets.local\"\n", original)
	if err == nil {
		t.Fatal("WriteConfig succeeded for output outside repository")
	}
	data, readErr := os.ReadFile(tomlPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != original {
		t.Fatalf("config changed after rejected write: %q", data)
	}
}

func TestReadConfigMissing(t *testing.T) {
	dir := t.TempDir()
	a := &App{RepositoryDir: dir}
	_, err := a.ReadConfig()
	if !apperr.Is(err, apperr.CodeConfigNotFound) {
		t.Fatalf("ReadConfig error = %v, want %q", err, apperr.CodeConfigNotFound)
	}
}

func TestWriteConfigProtectsTrustAndStorageLineage(t *testing.T) {
	dir := t.TempDir()
	current := `version = "v1alpha2"
workspace_id = "11111111-1111-4111-8111-111111111111"
control_genesis = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
default_env = "dev"

[env.dev]
output = ".env.dev"
incarnation = "22222222-2222-4222-8222-222222222222"

[env.legacy]
output = ".env.legacy"
`
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{RepositoryDir: dir}
	cases := map[string]struct{ from, to, key string }{
		"workspace":           {`workspace_id = "11111111-1111-4111-8111-111111111111"`, `workspace_id = "33333333-3333-4333-8333-333333333333"`, "workspace_id"},
		"genesis":             {`control_genesis = "sha256:aaaa`, `control_genesis = "sha256:bbbb`, "control_genesis"},
		"genesis dropped":     {"control_genesis = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n", "", "control_genesis"},
		"incarnation":         {`incarnation = "22222222-2222-4222-8222-222222222222"`, `incarnation = "44444444-4444-4444-8444-444444444444"`, "env.dev.incarnation"},
		"incarnation dropped": {"incarnation = \"22222222-2222-4222-8222-222222222222\"\n", "", "env.dev.incarnation"},
		"lineage given":       {"output = \".env.legacy\"\n", "output = \".env.legacy\"\nincarnation = \"55555555-5555-4555-8555-555555555555\"\n", "env.legacy.incarnation"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := a.WriteConfig(strings.Replace(current, c.from, c.to, 1), current)
			var appErr *apperr.Error
			if !apperr.Is(err, apperr.CodeConfigProtected) || !errors.As(err, &appErr) || appErr.Params()["key"] != c.key {
				t.Fatalf("WriteConfig = %v, want config_protected for %s", err, c.key)
			}
		})
	}
	data, _ := os.ReadFile(filepath.Join(dir, "enbu.toml"))
	if string(data) != current {
		t.Fatalf("a refused edit changed enbu.toml:\n%s", data)
	}

	// Everything else stays editable, including adding and removing environments.
	edited := strings.Replace(current, `default_env = "dev"`, `default_env = "legacy"`, 1)
	edited = strings.Replace(edited, "output = \".env.dev\"", "output = \"config/dev.env\"", 1)
	edited += "\n[env.new]\noutput = \".env.new\"\n"
	if err := a.WriteConfig(edited, current); err != nil {
		t.Fatalf("ordinary edit: %v", err)
	}
	withoutLegacy := strings.Replace(edited, "[env.legacy]\noutput = \".env.legacy\"\n", "", 1)
	withoutLegacy = strings.Replace(withoutLegacy, `default_env = "legacy"`, `default_env = "dev"`, 1)
	if err := a.WriteConfig(withoutLegacy, edited); err != nil {
		t.Fatalf("removing an environment: %v", err)
	}
}

// A current file that cannot be read may still name a trust root, so an edit
// that cannot be checked against it is refused rather than written blindly.
func TestWriteConfigFailsClosedOnAnUnreadableCurrentFile(t *testing.T) {
	dir := t.TempDir()
	broken := "version = \"v1alpha2\"\ncontrol_genesis = \"sha256:aaaa\"\n[env\n"
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{RepositoryDir: dir}
	if err := a.WriteConfig("version = \"v1alpha2\"\ncontrol_genesis = \"sha256:bbbb\"\n", broken); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("WriteConfig over an unreadable file = %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "enbu.toml")); string(data) != broken {
		t.Fatalf("enbu.toml was overwritten:\n%s", data)
	}
	// An unsupported version is still read for the values it protects.
	old := "version = \"v1alpha1\"\ncontrol_genesis = \"sha256:aaaa\"\n"
	if err := os.WriteFile(filepath.Join(dir, "enbu.toml"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.WriteConfig("version = \"v1alpha2\"\ncontrol_genesis = \"sha256:bbbb\"\n", old); !apperr.Is(err, apperr.CodeConfigProtected) {
		t.Fatalf("WriteConfig over an old version = %v", err)
	}
}

func TestWriteConfigIgnoresACustomOutput(t *testing.T) {
	dir := t.TempDir()
	a := &App{RepositoryDir: dir}
	if err := a.WriteConfig("version = \"v1alpha2\"\n[env.dev]\noutput = \"config/dev.env\"\n", ""); err != nil {
		t.Fatalf("WriteConfig: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil || !strings.Contains(string(data), "config/dev.env") {
		t.Fatalf(".gitignore = %q, %v", data, err)
	}
}

func TestCanceledDeleteReturnsWhileProjectLockIsHeld(t *testing.T) {
	a := newAlice(t)
	if err := a.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	fake := clockwork.NewFakeClock()
	a.Runtime = &Runtime{Clock: fake}
	lock, err := a.lockProject(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := a.DeleteEnvironment(ctx, "staging", true)
		result <- err
	}()
	wait, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	if err := fake.BlockUntilContext(wait, 1); err != nil {
		t.Fatalf("delete did not reach the lock retry timer: %v", err)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting delete: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delete waited for the project lock after cancellation")
	}
}

func TestProjectLockSurvivesGitCleanAndRetries(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is unavailable")
	}
	dir := t.TempDir()
	if out, err := exec.CommandContext(t.Context(), git, "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %s: %v", out, err)
	}
	fake := clockwork.NewFakeClock()
	a := &App{RepositoryDir: dir, Runtime: &Runtime{Clock: fake}}
	lock, err := a.lockProject(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if out, err := exec.CommandContext(t.Context(), git, "-C", dir, "clean", "-fd").CombinedOutput(); err != nil && runtime.GOOS != "windows" {
		t.Fatalf("git clean: %s: %v", out, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		next, err := a.lockProject(ctx)
		if next != nil {
			_ = next.Close()
		}
		result <- err
	}()
	if err := fake.BlockUntilContext(ctx, 1); err != nil {
		t.Fatalf("second lock did not wait after git clean: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	fake.Advance(time.Second)
	if err := <-result; err != nil {
		t.Fatalf("second lock did not retry successfully: %v", err)
	}
}

func TestProjectLockDoesNotDependOnGitMetadata(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	metadata := t.TempDir()
	if err := os.WriteFile(filepath.Join(metadata, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{first, second} {
		if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: "+metadata+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	lock, err := (&App{RepositoryDir: first}).lockProject(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	alsoLocked, err := (&App{RepositoryDir: second}).lockProject(ctx)
	if err != nil {
		t.Fatalf("another checkout could not lock independently: %v", err)
	}
	_ = alsoLocked.Close()

	// The same checkout must still contend when the external metadata is hidden.
	if err := os.Remove(filepath.Join(first, ".git")); err != nil {
		t.Fatal(err)
	}
	requireProjectLockBusy(t, &App{RepositoryDir: first})
}

func requireProjectLockBusy(t *testing.T, a *App) {
	t.Helper()
	copy := *a
	fake := clockwork.NewFakeClock()
	copy.Runtime = &Runtime{Clock: fake}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		lock, err := copy.lockProject(ctx)
		if lock != nil {
			_ = lock.Close()
		}
		result <- err
	}()
	if err := fake.BlockUntilContext(ctx, 1); err != nil {
		t.Fatalf("another caller did not wait for the project lock: %v", err)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("project lock wait: %v", err)
	}
}

func TestConfigWriteDoesNotReplaceSymlink(t *testing.T) {
	a := newAlice(t)
	path := a.projectPath()
	content, err := a.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(a.RepositoryDir, "linked.toml")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("file symlinks unavailable: %v", err)
	}
	if err := a.WriteConfig(content+"\n# edited\n", content); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("writing linked config: %v", err)
	}
	actual, err := os.Readlink(path)
	if err != nil || actual != target {
		t.Fatalf("configuration link changed: %s %v", actual, err)
	}
}

func TestConfigWriteKeepsPreviousContentsWhenGitignoreCannotBeUpdated(t *testing.T) {
	a := newAlice(t)
	path := filepath.Join(a.RepositoryDir, ".gitignore")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := a.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteConfig(before+"\n# edited\n", before); err == nil {
		t.Fatal("expected .gitignore update failure")
	}
	after, err := a.ReadConfig()
	if err != nil || after != before {
		t.Fatalf("configuration was changed: %v", err)
	}
}

func TestConfigWriteKeepsExclusionsWhenFileReplacementFails(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows file replacement rejects a read-only destination")
	}
	a := newAlice(t)
	if err := a.CreateEnvironment("staging"); err != nil {
		t.Fatal(err)
	}
	before, err := a.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	path := a.projectPath()
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(path, 0o600) }()
	content := strings.Replace(before, ".env.staging", "sensitive.generated", 1)
	if err := a.WriteConfig(content, before); err == nil {
		t.Fatal("expected replacement of read-only config to fail")
	}
	actual, err := a.ReadConfig()
	if err != nil || actual != before {
		t.Fatalf("configuration changed: %v", err)
	}
	rules, err := os.ReadFile(filepath.Join(a.RepositoryDir, ".gitignore"))
	if err != nil || !strings.Contains(string(rules), "/sensitive.generated") {
		t.Fatalf("output exclusion not retained: %v", err)
	}
}

package simulation

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/opencontainers/go-digest"
)

// fixtureGit invokes the real Git with a fixed commit clock and no inherited
// repository/index/config overrides. Hashes and path-bearing output never enter
// the replay oracle: the assertions concern config bytes and real App behavior.
func fixtureGit(ctx context.Context, dir string, args ...string) ([]byte, error) {
	base := []string{"-c", "core.hooksPath=" + filepath.Join(dir, ".disabled-hooks"), "-c", "commit.gpgSign=false", "-c", "tag.gpgSign=false", "-c", "core.autocrlf=false", "-c", "core.longpaths=true", "-c", "gc.auto=0", "-c", "user.name=Simulation", "-c", "user.email=simulation@example.invalid"}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...)
	cmd.Dir = dir
	for _, value := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(value), "GIT_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_DATE=2023-11-14T22:13:20+00:00", "GIT_COMMITTER_DATE=2023-11-14T22:13:20+00:00")
	return cmd.CombinedOutput()
}

func (w *World) GitWorktrees(ctx context.Context) error {
	primary := w.Devices[0]
	dir := primary.App.RepositoryDir
	git := func(at string, args ...string) error {
		output, err := fixtureGit(ctx, at, args...)
		if err != nil {
			return fmt.Errorf("fixture git %v: %w: %s", args, err, output)
		}
		return nil
	}
	commit := func(at, message string) error {
		if err := git(at, "add", "--", "enbu.toml"); err != nil {
			return err
		}
		return git(at, "commit", "-m", message)
	}
	read := func(a *app.App, env string, want map[string]string) error {
		got, err := a.ListSecrets(ctx, env)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("git checkout %s data = %v, want %v", env, got, want)
		}
		return w.Tape.Observe("git-worktree-read", env, got)
	}
	if err := primary.App.CreateEnvironment("staging"); err != nil {
		return err
	}
	if err := primary.App.AddSecret(ctx, "staging", "TOKEN", "old-deployment"); err != nil {
		return err
	}
	if err := primary.App.SwitchEnvironment("default"); err != nil {
		return err
	}
	w.Model["staging"] = map[string]string{"TOKEN": "old-deployment"}
	if err := w.Share(0); err != nil {
		return err
	}
	if err := w.Check(ctx, "staging"); err != nil {
		return err
	}
	if err := git(dir, "init", "--initial-branch=main", "--template="); err != nil {
		return err
	}
	if err := commit(dir, "shared workspace baseline"); err != nil {
		return err
	}
	if err := git(dir, "tag", "baseline"); err != nil {
		return err
	}
	checkout := filepath.Join(w.Root, "git-feature-worktree")
	if err := git(dir, "worktree", "add", "-b", "feature", checkout, "main"); err != nil {
		return err
	}
	keys := &Keys{Tape: w.Tape, Device: 0, workspaces: primary.Keys.workspaces}
	store := &Store{Store: primary.Store.Store, Tape: w.Tape, Device: 1, advance: primary.Store.advance}
	process := w.newApp(0, len(w.Devices), keys, store)
	process.RepositoryDir = checkout
	path, err := config.ProjectConfigPathFrom(checkout)
	if err != nil || filepath.Dir(path) != checkout {
		return fmt.Errorf("worktree has no independent config: %s %v", path, err)
	}
	if process.CheckpointDir != primary.App.CheckpointDir || process.CacheDir != primary.App.CacheDir || process.Runtime.LocalStateDir != primary.App.Runtime.LocalStateDir {
		return fmt.Errorf("worktree failed to share personal durable state")
	}
	// Main migrates production while the feature branch retains the old config.
	if err := primary.App.RenameEnvironment("staging", "production"); err != nil {
		return err
	}
	if err := primary.App.CreateEnvironment("staging"); err != nil {
		return err
	}
	if err := primary.App.AddSecret(ctx, "staging", "TOKEN", "new-sandbox"); err != nil {
		return err
	}
	w.Model["production"] = map[string]string{"TOKEN": "old-deployment"}
	w.Model["staging"] = map[string]string{"TOKEN": "new-sandbox"}
	mainConfig, err := config.LoadProjectFrom(dir)
	if err != nil {
		return err
	}
	mainConfig.SetDefault("production")
	if err := config.SaveProjectTo(dir, mainConfig); err != nil {
		return err
	}
	if err := commit(dir, "rename deployment and recreate sandbox"); err != nil {
		return err
	}
	// The stale name still addresses its original incarnation. Two worktrees of
	// one user publish disjoint updates to that one resource under different names.
	teammate := w.Devices[1]
	w.Devices[1] = &Device{App: process, Keys: keys, Store: store, ID: primary.ID}
	err = func() error {
		defer func() { w.Devices[1] = teammate }()
		return w.Batch(ctx, "publish", []func(int) error{
			func(int) error { return primary.App.AddSecret(ctx, "production", "MAIN_WORK", "kept") },
			func(int) error { return process.AddSecret(ctx, "staging", "FEATURE_WORK", "kept") },
		})
	}()
	if err != nil {
		return err
	}
	w.Model["production"]["MAIN_WORK"] = "kept"
	w.Model["production"]["FEATURE_WORK"] = "kept"
	if err := read(process, "staging", w.Model["production"]); err != nil {
		return err
	}
	if err := read(primary.App, "production", w.Model["production"]); err != nil {
		return err
	}
	if err := read(primary.App, "staging", w.Model["staging"]); err != nil {
		return err
	}
	if err := process.CreateEnvironment("preview"); err != nil {
		return err
	}
	if err := process.AddSecret(ctx, "preview", "TOKEN", "feature-preview"); err != nil {
		return err
	}
	w.Model["preview"] = map[string]string{"TOKEN": "feature-preview"}
	featureConfig, err := config.LoadProjectFrom(checkout)
	if err != nil {
		return err
	}
	featureConfig.SetDefault("preview")
	if err := config.SaveProjectTo(checkout, featureConfig); err != nil {
		return err
	}
	if err := commit(checkout, "add feature preview and choose its default"); err != nil {
		return err
	}
	// The team default changed differently in both branches: Git must produce
	// conflict markers, and enbu must stop before touching untrusted storage.
	output, mergeErr := fixtureGit(ctx, checkout, "merge", "--no-edit", "main")
	if mergeErr == nil {
		return fmt.Errorf("fixture Git merge unexpectedly avoided conflict: %s", output)
	}
	conflicted, err := os.ReadFile(filepath.Join(checkout, "enbu.toml"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(conflicted), "<<<<<<<") {
		return fmt.Errorf("git merge failed without a config conflict: %s", output)
	}
	start := len(w.Tape.Recording.Entries)
	if got, err := process.ListSecrets(ctx, "default"); err == nil || len(got) != 0 {
		return fmt.Errorf("unresolved Git conflict returned secrets: %v %v", got, err)
	}
	for _, entry := range w.Tape.Recording.Entries[start:] {
		if entry.Kind == "storage-request" {
			return fmt.Errorf("unresolved config conflict reached storage")
		}
	}
	// Resolve the public config deliberately. Preserve both deployment identities
	// and add the feature environment, rather than accepting one branch wholesale.
	merged, err := config.LoadProjectFrom(dir)
	if err != nil {
		return err
	}
	merged.Environments["preview"] = featureConfig.Environments["preview"]
	if err := config.SaveProjectTo(checkout, merged); err != nil {
		return err
	}
	if err := commit(checkout, "resolve workspace configuration conflict"); err != nil {
		return err
	}
	if err := git(dir, "merge", "--ff-only", "feature"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	for _, env := range []string{"default", "production", "staging", "preview"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
		if err := read(process, env, w.Model[env]); err != nil {
			return err
		}
	}
	// Returning to an old branch must neither mix its staging incarnation with
	// the new sandbox nor erase a personal selection absent from that old config.
	if err := process.SwitchEnvironment("preview"); err != nil {
		return err
	}
	if err := git(checkout, "switch", "--detach", "baseline"); err != nil {
		return err
	}
	if current, err := process.CurrentEnvironment(); err != nil || current != "default" {
		return fmt.Errorf("old checkout selection fallback: %s %v", current, err)
	}
	if current, err := primary.App.CurrentEnvironment(); err != nil || current != "preview" {
		return fmt.Errorf("old checkout erased personal selection: %s %v", current, err)
	}
	if err := process.AddSecret(ctx, "staging", "OLD_BRANCH_WORK", "kept"); err != nil {
		return err
	}
	w.Model["production"]["OLD_BRANCH_WORK"] = "kept"
	if err := read(primary.App, "production", w.Model["production"]); err != nil {
		return err
	}
	if err := read(primary.App, "staging", w.Model["staging"]); err != nil {
		return err
	}
	// Git moves its linked-worktree metadata too. Use a path with spaces and
	// Unicode to exercise argument/path handling without changing identity.
	moved := filepath.Join(w.Root, "moved worktree 日本語")
	if err := git(dir, "worktree", "move", checkout, moved); err != nil {
		return err
	}
	if _, err := os.Stat(checkout); !os.IsNotExist(err) {
		return fmt.Errorf("git kept old worktree path: %v", err)
	}
	checkout = moved
	process.SetRepositoryDir(checkout)
	if err := read(process, "staging", w.Model["production"]); err != nil {
		return err
	}
	// A commit may name a different root; Git branch changes grant no trust.
	if err := git(checkout, "switch", "-c", "untrusted-config"); err != nil {
		return err
	}
	untrusted, err := config.LoadProjectFrom(checkout)
	if err != nil {
		return err
	}
	untrusted.ControlGenesis = digest.FromString("foreign Git configuration root").String()
	if err := config.SaveProjectTo(checkout, untrusted); err != nil {
		return err
	}
	if err := commit(checkout, "foreign trust root"); err != nil {
		return err
	}
	if _, err := process.ListSecrets(ctx, "default"); requireCode(err, apperr.CodeTrustRootChanged) != nil {
		return fmt.Errorf("git commit silently replaced pinned root: %v", err)
	}
	if err := git(checkout, "switch", "feature"); err != nil {
		return err
	}
	tracked, err := fixtureGit(ctx, dir, "ls-files")
	if err != nil || strings.TrimSpace(string(tracked)) != "enbu.toml" {
		return fmt.Errorf("fixture tracked private state: %s %v", tracked, err)
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	for _, env := range []string{"default", "production", "staging", "preview"} {
		if err := w.Check(ctx, env); err != nil {
			return err
		}
		if err := read(process, env, w.Model[env]); err != nil {
			return err
		}
	}
	return nil
}

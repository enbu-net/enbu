package main

import (
	"encoding/json"
	"fmt"
	"go/build"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

func readYAML(t *testing.T, path string) *yaml.Node {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Content[0]
}

func TestGoCacheSeparatesWorkloadsAndIncludesNestedModules(t *testing.T) {
	root := readYAML(t, "../../.github/actions/setup-go/action.yaml")
	steps := field(field(root, "runs"), "steps")
	script := field(steps.Content[1], "run").Value
	for _, scope := range []string{"$RUNNER_OS", "$RUNNER_ARCH", "$CACHE_SCOPE"} {
		if !strings.Contains(script, scope) {
			t.Fatalf("Go cache prefix omits %s", scope)
		}
	}
	if field(field(steps.Content[1], "env"), "CACHE_SCOPE").Value != "${{ inputs.cache-scope }}" {
		t.Fatal("independent build populations would share one cache")
	}
	for _, step := range steps.Content[2:] {
		key := field(field(step, "with"), "key").Value
		for _, required := range []string{"steps.go.outputs.prefix", "go.sum", "tools/wails3/go.sum", "github.run_id"} {
			if !strings.Contains(key, required) {
				t.Fatalf("Go cache key omits %s", required)
			}
		}
	}
}

// A cache key fixed by go.sum is saved once and restored unchanged forever.
// main saves a new entry on every run; every other run only restores.
func TestOnlyMainSavesTheGoCaches(t *testing.T) {
	steps := field(field(readYAML(t, "../../.github/actions/setup-go/action.yaml"), "runs"), "steps")
	if field(field(steps.Content[0], "with"), "cache").Value != "false" {
		t.Fatal("actions/setup-go saves its own immutable cache")
	}
	want := map[string]string{
		"actions/cache@":         "inputs.cache == 'true' && github.ref == 'refs/heads/main'",
		"actions/cache/restore@": "inputs.cache == 'true' && github.ref != 'refs/heads/main'",
	}
	for _, step := range steps.Content[2:] {
		uses := field(step, "uses").Value
		action := uses[:strings.Index(uses, "@")+1]
		if field(step, "if").Value != want[action] {
			t.Fatalf("%s runs where it must not: %s", uses, field(step, "if").Value)
		}
		delete(want, action)
	}
	if len(want) != 0 {
		t.Fatalf("missing cache steps: %v", want)
	}
}

func TestAquaCacheUsesTheSameIsolatedRootOnWindowsAndUnix(t *testing.T) {
	root := readYAML(t, "../../.github/actions/setup-tools/action.yaml")
	steps := field(field(root, "runs"), "steps")
	script := field(steps.Content[0], "run").Value
	for _, temp := range []string{t.TempDir(), `D:\a\_temp`} {
		output := filepath.Join(t.TempDir(), "env")
		cmd := exec.CommandContext(t.Context(), "bash", "-eu", "-c", script)
		cmd.Env = append(os.Environ(), "RUNNER_TEMP="+temp, "GITHUB_ENV="+output)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "AQUA_ROOT_DIR="+temp+"/enbu-aqua\n" {
			t.Fatalf("wrong installer root: %q", data)
		}
	}
	with := field(steps.Content[1], "with")
	if field(with, "path").Value != "${{ runner.temp }}/enbu-aqua" {
		t.Fatal("cache does not cover the root passed to aqua")
	}
	for _, name := range []string{"key"} {
		key := field(with, name).Value
		for _, scope := range []string{"runner.os", "runner.arch", "inputs.cache-scope"} {
			if !strings.Contains(key, scope) {
				t.Fatalf("%s shares a cache across %s", name, scope)
			}
		}
	}
}

// GitHub Releases answers 504 for minutes at a time, so every download from
// it gets one retry after a pause.
func requireOneDelayedRetry(t *testing.T, path, action, versionKey string, check func(with *yaml.Node)) {
	t.Helper()
	root := readYAML(t, path)
	var first, version string
	waited, retries := false, 0
	for _, step := range field(field(root, "runs"), "steps").Content {
		uses := field(step, "uses")
		if uses == nil || !strings.HasPrefix(uses.Value, action+"@") {
			if first != "" && retries == 0 && field(step, "run") != nil && strings.HasPrefix(field(step, "run").Value, "sleep ") {
				waited = field(step, "if").Value == "steps."+first+".outcome == 'failure'"
			}
			continue
		}
		with := field(step, "with")
		if check != nil {
			check(with)
		}
		if first == "" {
			if field(step, "continue-on-error").Value != "true" {
				t.Fatalf("%s: a failed first install does not reach the retry", path)
			}
			first = field(step, "id").Value
			version = field(with, versionKey).Value
			continue
		}
		if field(step, "if").Value != "steps."+first+".outcome == 'failure'" {
			t.Fatalf("%s: the retry does not run only after a failed first install", path)
		}
		if field(with, versionKey).Value != version {
			t.Fatalf("%s: the retry installs a different version", path)
		}
		retries++
	}
	if first == "" || retries != 1 || !waited {
		t.Fatalf("%s: want one install, a wait and one retry, got first=%q waited=%t retries=%d", path, first, waited, retries)
	}
}

func TestAquaInstallSkipsCachedAquaAndRetriesOnce(t *testing.T) {
	requireOneDelayedRetry(t, "../../.github/actions/setup-tools/action.yaml", "aquaproj/aqua-installer", "aqua_version", func(with *yaml.Node) {
		// aqua-installer skips only when aqua is already on PATH, so a cold
		// cache still installs it.
		if field(with, "skip_install_aqua").Value != "true" {
			t.Fatal("aqua is downloaded again although the cache restored it")
		}
	})
}

func TestTobariInstallRetriesOnce(t *testing.T) {
	requireOneDelayedRetry(t, "../../.github/actions/setup-coverage/action.yaml", "goccy/tobari-action/setup", "version", nil)
}

func TestFullDSTRunnerGroupsCoverEveryLogicalLaneOnce(t *testing.T) {
	job := statusJob(t, "simulation.yaml", "simulation")
	matrix := field(field(job, "strategy"), "matrix")
	expression := field(matrix, "group").Value
	choices := regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(expression, -1)
	var arrays []string
	for _, choice := range choices {
		if strings.HasPrefix(choice[1], "[") {
			arrays = append(arrays, choice[1])
		}
	}
	if len(arrays) != 2 {
		t.Fatalf("expected full and incremental groups: %s", expression)
	}
	for index, size := range []int{32, 4} {
		var groups []struct {
			ID    int   `json:"id"`
			Lanes []int `json:"lanes"`
		}
		if err := json.Unmarshal([]byte(arrays[index]), &groups); err != nil {
			t.Fatal(err)
		}
		seen := map[int]bool{}
		for _, group := range groups {
			if len(group.Lanes) != 4 {
				t.Fatal("a runner must have exactly four native parallel lanes")
			}
			for _, lane := range group.Lanes {
				if lane < 0 || lane >= size || seen[lane] {
					t.Fatalf("overlapping/out-of-range lane %d", lane)
				}
				seen[lane] = true
			}
		}
		if len(seen) != size {
			t.Fatalf("missing logical lanes: %v", seen)
		}
	}
	seeds := field(field(job, "env"), "ENBU_SIM_SEEDS").Value
	shards := field(field(job, "env"), "ENBU_SIM_SHARDS").Value
	values := regexp.MustCompile(`&& '(\d+)' \|\| '(\d+)'`)
	seedValues, shardValues := values.FindStringSubmatch(seeds), values.FindStringSubmatch(shards)
	if len(seedValues) != 3 || len(shardValues) != 3 {
		t.Fatal("missing full/incremental seed budgets")
	}
	for i, expected := range []int{1024, 8} {
		seedCount, _ := strconv.Atoi(seedValues[i+1])
		laneCount, _ := strconv.Atoi(shardValues[i+1])
		if seedCount*laneCount != expected {
			t.Fatalf("mode %d changes seed budget: %d * %d", i, seedCount, laneCount)
		}
	}
	if field(field(job, "strategy"), "max-parallel").Value != "5" {
		t.Fatal("full exploration can monopolize routine CI capacity")
	}
	steps := field(job, "steps")
	for _, step := range steps.Content {
		if lanes := field(step, "parallel"); lanes != nil {
			for i, lane := range lanes.Content {
				want := fmt.Sprintf("${{ matrix.group.lanes[%d] }}", i)
				if field(field(lane, "env"), "ENBU_SIM_SHARD").Value != want {
					t.Fatal("parallel step uses another group's shard")
				}
				if !strings.Contains(field(lane, "run").Value, `-coverprofile="$ENBU_SIM_ARTIFACTS/coverage.out"`) {
					t.Fatal("coverage output is not lane-local")
				}
			}
		}
	}
}

func TestSharedFrontendPrecedesParallelReadersAndAllCIResultsAreRequired(t *testing.T) {
	root := readYAML(t, "../../.github/workflows/ci.yaml")
	jobs := field(root, "jobs")
	producer := field(jobs, "frontend")
	sharedRoutes := false
	for _, step := range field(producer, "steps").Content {
		if uses := field(step, "uses"); uses != nil && strings.HasPrefix(uses.Value, "actions/upload-artifact@") {
			sharedRoutes = strings.Contains(field(field(step, "with"), "path").Value, "web/src/routeTree.gen.ts")
		}
	}
	if !sharedRoutes {
		t.Fatal("prebuilt GUI readers lack the generated router types")
	}
	for _, name := range []string{"lint", "test", "desktop", "scenario"} {
		job := field(jobs, name)
		if needs := field(job, "needs"); needs == nil || len(needs.Content) != 1 || needs.Content[0].Value != "frontend" {
			t.Fatalf("%s may read frontend output before its producer finishes", name)
		}
		if field(field(job, "env"), "ENBU_FRONTEND_PREBUILT").Value != "1" {
			t.Fatalf("%s rebuilds shared output", name)
		}
	}
	needs := field(field(jobs, "status-check"), "needs")
	for i := 0; i < len(jobs.Content); i += 2 {
		name := jobs.Content[i].Value
		if name == "status-check" {
			continue
		}
		found := false
		for _, dependency := range needs.Content {
			found = found || dependency.Value == name
		}
		if !found {
			t.Fatalf("required Check can ignore %s", name)
		}
	}
	job := field(jobs, "test")
	prepared := false
	for _, step := range field(job, "steps").Content {
		if name := field(step, "name"); name != nil && name.Value == "Prepare frontend dependencies" {
			prepared = true
		}
		if parallel := field(step, "parallel"); parallel != nil && field(parallel.Content[0], "name") != nil {
			if !prepared || len(parallel.Content) != 4 {
				t.Fatal("parallel tests may race dependency installation or omit a suite")
			}
		}
	}
}

func TestPrebuiltFrontendRequiresBothFlagAndExpectedArtifacts(t *testing.T) {
	task, err := exec.LookPath("task")
	if err != nil {
		t.Skip("task is not installed")
	}
	// Resolve the actual binary before entering a fixture without aqua.yaml.
	// CI puts aqua's context-dependent task shim on PATH.
	if aqua, err := exec.LookPath("aqua"); err == nil {
		resolved, err := exec.CommandContext(t.Context(), aqua, "which", "task").Output()
		if err == nil {
			task = strings.TrimSpace(string(resolved))
		}
	}
	raw, err := os.ReadFile("../../Taskfile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, target, flag     string
		desktop, extension, ok bool
	}{
		{"desktop-ready", "frontend/build/desktop", "1", true, false, true},
		{"both-ready", "frontend/build", "1", true, true, true},
		{"missing-desktop", "frontend/build/desktop", "1", false, false, false},
		{"missing-extension", "frontend/build", "1", true, false, false},
		{"flag-required", "frontend/build/desktop", "", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "Taskfile.yaml"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			for _, subtree := range []string{"web", "vscode", "bin"} {
				if err := os.MkdirAll(filepath.Join(dir, subtree), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, artifact := range []struct {
				present bool
				path    string
			}{{tc.desktop, "web/dist"}, {tc.extension, "web/dist-vscode"}} {
				if !artifact.present {
					continue
				}
				path := filepath.Join(dir, artifact.path)
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "index.html"), []byte("same-run artifact"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// A missing artifact must attempt a rebuild, which deliberately fails here.
			if err := os.WriteFile(filepath.Join(dir, "bin/vp"), []byte("#!/bin/sh\nexit 23\n"), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), task, tc.target)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "ENBU_FRONTEND_PREBUILT="+tc.flag, "PATH="+filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("prebuilt check: %v\n%s", err, out)
			}
		})
	}
}

func TestWindowsCompositeSetupIsSerialAndUnixSetupRunsOnce(t *testing.T) {
	root := readYAML(t, "../../.github/workflows/ci.yaml")
	jobs := field(root, "jobs")
	for _, jobName := range []string{"core-native", "identity-e2e", "desktop"} {
		job := field(jobs, jobName)
		for _, osName := range []string{"Windows", "Linux", "macOS"} {
			counts := map[string]int{}
			selected := func(step *yaml.Node) bool {
				condition := field(step, "if")
				if condition == nil {
					return true
				}
				switch condition.Value {
				case "runner.os == 'Windows'":
					return osName == "Windows"
				case "runner.os != 'Windows'":
					return osName != "Windows"
				case "runner.os == 'Linux'":
					return osName == "Linux"
				case "runner.os != 'Linux'":
					return osName != "Linux"
				default:
					t.Fatalf("unsupported setup guard %s", condition.Value)
					return false
				}
			}
			collect := func(step *yaml.Node, parallel bool) {
				uses := field(step, "uses")
				if uses == nil || !strings.HasPrefix(uses.Value, "$/.github/actions/") || !selected(step) {
					return
				}
				if parallel && osName == "Windows" {
					t.Fatalf("%s races the Windows runner event file", jobName)
				}
				counts[uses.Value]++
			}
			for _, step := range field(job, "steps").Content {
				if group := field(step, "parallel"); group != nil {
					for _, child := range group.Content {
						collect(child, true)
					}
				} else {
					collect(step, false)
				}
			}
			for _, name := range []string{"setup-go", "setup-tools"} {
				if counts["$/.github/actions/"+name] != 1 {
					t.Fatalf("%s %s does not prepare %s exactly once: %v", jobName, osName, name, counts)
				}
			}
		}
	}
}

// Scenario tags exist only in the CLI mocks and scenario harness. Re-running
// unrelated app/desktop/core/DST tests with that tag repeats the unit job.
// Any newly tagged package must be added explicitly, even if its tagged file is
// only a helper/init function: it could change the behavior of ordinary tests.
func TestScenarioTargetsCoverEveryScenarioTaggedPackage(t *testing.T) {
	root := readYAML(t, "../../Taskfile.yaml")
	target := field(field(root, "tasks"), "cli/test/scenario")
	packages := map[string]bool{}
	for _, cmd := range field(target, "cmds").Content {
		if strings.HasPrefix(cmd.Value, "go test ") {
			for _, arg := range strings.Fields(cmd.Value) {
				if strings.HasPrefix(arg, "./") {
					packages[strings.TrimPrefix(arg, "./")] = true
				}
			}
		}
	}
	if packages["..."] || len(packages) == 0 {
		t.Fatal("scenario suite repeats all unit/DST packages or has no target")
	}
	base := build.Default
	base.BuildTags = append(append([]string(nil), base.BuildTags...), "fixture")
	scenario := base
	scenario.BuildTags = append(append([]string(nil), base.BuildTags...), "scenario")
	scanned := 0
	err := filepath.WalkDir("../..", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".tmp", ".kotowari", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		included, err := scenario.MatchFile(filepath.Dir(path), entry.Name())
		if err != nil || !included {
			return err
		}
		included, err = base.MatchFile(filepath.Dir(path), entry.Name())
		if err != nil || included {
			return err
		}
		scanned++
		relative, err := filepath.Rel("../..", filepath.Dir(path))
		if err != nil {
			return err
		}
		if !packages[filepath.ToSlash(relative)] {
			t.Errorf("scenario-tagged package %s is omitted: %s", relative, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("no scenario-tagged files were inspected")
	}
}

// Pull requests are the checks; a merge must not queue the same jobs again,
// and a newer push must replace the run of the push before it.
func TestPullRequestChecksDoNotRunAgainOnMainAndCancelSupersededRuns(t *testing.T) {
	for _, name := range []string{"ci.yaml", "preview.yaml", "actionlint.yaml"} {
		t.Run(name, func(t *testing.T) {
			root := readYAML(t, "../../.github/workflows/"+name)
			if field(field(root, "on"), "push") != nil {
				t.Fatal("main pushes repeat the pull request checks")
			}
			concurrency := field(root, "concurrency")
			// Workflows that also run on main cancel only pull request runs, so a
			// manual run and the nightly one do not cancel each other.
			want := "true"
			if field(field(root, "on"), "schedule") != nil {
				want = "${{ github.event_name == 'pull_request' }}"
			}
			if cancel := field(concurrency, "cancel-in-progress"); cancel == nil || cancel.Value != want {
				t.Fatalf("cancel-in-progress must be %s", want)
			}
			group := field(concurrency, "group")
			if group == nil || !strings.Contains(group.Value, "github.event.pull_request.number || github.ref") {
				t.Fatal("runs of one pull request do not share a concurrency group")
			}
		})
	}
}

// jobNeeds lists a job's needs, written as one name or as a list.
func jobNeeds(job *yaml.Node) []string {
	needs := field(job, "needs")
	switch {
	case needs == nil:
		return nil
	case needs.Kind == yaml.ScalarNode:
		return []string{needs.Value}
	}
	out := make([]string, 0, len(needs.Content))
	for _, n := range needs.Content {
		out = append(out, n.Value)
	}
	return out
}

// A job that starts without needs must wait for the changes job, or a
// docs-only pull request runs it anyway.
func TestCIJobsFollowTheChangesSelection(t *testing.T) {
	jobs := field(readYAML(t, "../../.github/workflows/ci.yaml"), "jobs")
	for i := 0; i < len(jobs.Content); i += 2 {
		name, job := jobs.Content[i].Value, jobs.Content[i+1]
		needs := jobNeeds(job)
		if name == "changes" || name == "status-check" || name == "renovate-config" || len(needs) > 0 && needs[0] != "changes" {
			continue
		}
		condition := field(job, "if")
		if len(needs) != 1 || condition == nil || !strings.HasPrefix(condition.Value, "needs.changes.outputs.") {
			t.Fatalf("%s runs regardless of the changed paths", name)
		}
	}
}

// Closing a pull request must cancel its checks without a runner: a cancelling
// job would wait in the same jammed queue as the runs it cancels. A closed
// event joins the PR's concurrency group with a run whose jobs all skip.
func TestClosingAPullRequestCancelsItsRunsWithoutARunner(t *testing.T) {
	const notClosed = "github.event.action != 'closed'"
	const prOnly = "${{ github.event_name == 'pull_request' }}"
	// The group is what does the cancelling: the closed run must land in the
	// same group as the runs of its pull request (DST: its branch's push runs).
	concurrency := map[string][2]string{
		"ci.yaml":      {"ci-${{ github.event.pull_request.number || github.ref }}", prOnly},
		"preview.yaml": {"preview-${{ github.event.pull_request.number || github.ref }}", "true"},
		"simulation.yaml": {
			"simulation-${{ github.event_name == 'pull_request' && format('push-refs/heads/{0}', github.head_ref) || format('{0}-{1}', github.event_name, github.ref) }}",
			"${{ github.event_name == 'push' || github.event_name == 'pull_request' }}",
		},
	}
	for name, want := range concurrency {
		t.Run(name, func(t *testing.T) {
			root := readYAML(t, "../../.github/workflows/"+name)
			closed := false
			for _, n := range field(field(field(root, "on"), "pull_request"), "types").Content {
				closed = closed || n.Value == "closed"
			}
			if !closed {
				t.Fatal("closing a pull request leaves its runs queued")
			}
			group, cancel := field(field(root, "concurrency"), "group"), field(field(root, "concurrency"), "cancel-in-progress")
			if group == nil || group.Value != want[0] {
				t.Fatalf("the closed run does not join the group of the runs it must cancel: want %q", want[0])
			}
			if cancel == nil || cancel.Value != want[1] {
				t.Fatalf("the closed run cannot cancel the runs of its group: want cancel-in-progress %q", want[1])
			}
			jobs := field(root, "jobs")
			for i := 0; i < len(jobs.Content); i += 2 {
				job := jobs.Content[i+1]
				condition := field(job, "if")
				if len(jobNeeds(job)) > 0 && (condition == nil || !strings.HasPrefix(condition.Value, "always()")) {
					continue // skipped with the jobs it needs
				}
				if condition == nil || !strings.Contains(condition.Value, notClosed) {
					t.Fatalf("%s takes a runner when the pull request closes", jobs.Content[i].Value)
				}
			}
		})
	}
}

// CI already runs every coverage suite on each pull request, so coverage must
// not run them a second time there: it is a nightly report, also run by hand.
func TestCoverageRunsOnlyNightlyAndByHand(t *testing.T) {
	on := field(readYAML(t, "../../.github/workflows/tobari.yaml"), "on")
	for i := 0; i < len(on.Content); i += 2 {
		if event := on.Content[i].Value; event != "schedule" && event != "workflow_dispatch" {
			t.Fatalf("coverage runs on %s", event)
		}
	}
	if field(on, "workflow_dispatch") == nil {
		t.Fatal("coverage cannot be run by hand")
	}
	schedule := field(on, "schedule")
	if schedule == nil || len(schedule.Content) != 1 {
		t.Fatal("coverage needs exactly one nightly schedule")
	}
	cron := strings.Fields(field(schedule.Content[0], "cron").Value)
	if len(cron) != 5 || cron[2] != "*" || cron[3] != "*" || cron[4] != "*" {
		t.Fatalf("coverage schedule %v is not daily", cron)
	}
}

func TestGoCoverageDoesNotDependOnReactTestResults(t *testing.T) {
	root := readYAML(t, "../../.github/workflows/tobari.yaml")
	jobs := field(root, "jobs")
	for _, name := range []string{"unit", "scenario", "frontend"} {
		job := field(jobs, name)
		needs := field(job, "needs")
		if needs == nil || len(needs.Content) != 1 || needs.Content[0].Value != "embed" {
			t.Fatalf("%s must wait only for the shared build", name)
		}
		download := false
		for _, step := range field(job, "steps").Content {
			if uses := field(step, "uses"); uses != nil && strings.HasPrefix(uses.Value, "actions/download-artifact@") {
				with := field(step, "with")
				download = field(with, "name").Value == "coverage-embed" && field(with, "path").Value == "web"
			}
		}
		if !download || field(field(job, "env"), "ENBU_FRONTEND_PREBUILT").Value != "1" {
			t.Fatalf("%s lacks the shared bundle before skipping its frontend build", name)
		}
	}
	embed := field(jobs, "embed")
	if embed == nil || field(embed, "needs") != nil {
		t.Fatal("embed build must not wait for coverage tests")
	}
	bundle, routes, build := false, false, false
	for _, step := range field(embed, "steps").Content {
		if run := field(step, "run"); run != nil {
			build = build || run.Value == "task frontend/build/desktop"
			if strings.Contains(run.Value, "test") {
				t.Fatal("a test failure can suppress independent Go coverage")
			}
		}
		if uses := field(step, "uses"); uses != nil && strings.HasPrefix(uses.Value, "actions/upload-artifact@") {
			paths := field(field(step, "with"), "path").Value
			bundle = strings.Contains(paths, "web/dist")
			routes = strings.Contains(paths, "web/src/routeTree.gen.ts")
		}
	}
	if !build || !bundle || !routes {
		t.Fatal("shared coverage artifact lacks its bundle or generated router")
	}
}

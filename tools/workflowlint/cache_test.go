package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
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
	script := field(steps.Content[0], "run").Value
	var hashes [2][32]byte
	for i, scope := range []string{"core-native", "coverage-unit"} {
		dir := t.TempDir()
		cmd := exec.CommandContext(t.Context(), "bash", "-eu", "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CACHE_SCOPE="+scope)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		data, err := os.ReadFile(filepath.Join(dir, ".tmp/go-cache-scope"))
		if err != nil {
			t.Fatal(err)
		}
		hashes[i] = sha256.Sum256(data)
	}
	if hashes[0] == hashes[1] {
		t.Fatal("independent build populations would race for the same immutable cache")
	}
	paths := field(field(steps.Content[1], "with"), "cache-dependency-path").Value
	for _, required := range []string{"go.sum", "tools/wails3/go.sum", ".tmp/go-cache-scope"} {
		if !strings.Contains(paths, required) {
			t.Fatalf("Go cache omits %s", required)
		}
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
	for index, size := range []int{16, 4} {
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
	if field(field(job, "strategy"), "max-parallel").Value != "${{ needs.plan.outputs.mode == 'full' && 10 || 5 }}" {
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
	for _, name := range []string{"check", "test", "desktop", "scenario"} {
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

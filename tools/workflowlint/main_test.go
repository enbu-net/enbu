package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestNormalizePreservesEveryParallelChildForActionlint(t *testing.T) {
	input := []byte("name: test\non: push\njobs:\n  test:\n    runs-on: ubuntu-26.04\n    steps:\n      - parallel:\n          - name: first\n            run: echo first\n            env:\n              VALUE: kept\n          - name: second\n            uses: actions/checkout@v7.0.1\n      - run: echo after\n")
	data, err := normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	steps := field(field(field(doc.Content[0], "jobs"), "test"), "steps")
	if len(steps.Content) != 3 || field(steps.Content[0], "run").Value != "echo first" || field(steps.Content[1], "uses").Value != "actions/checkout@v7.0.1" || field(field(steps.Content[0], "env"), "VALUE").Value != "kept" {
		t.Fatalf("lost child validation: %s", data)
	}
}
func TestNormalizeRejectsMalformedParallelGroups(t *testing.T) {
	for _, group := range []string{
		"parallel: []",
		"parallel: true",
		"parallel: [{run: echo ok}]\n        run: echo invalid",
		"parallel: [{parallel: [{run: echo nested}]}]",
		"parallel: [{background: true, run: echo invalid}]",
	} {
		t.Run(group, func(t *testing.T) {
			_, err := normalize([]byte("jobs:\n  test:\n    steps:\n      - " + group + "\n"))
			if err == nil {
				t.Fatal("invalid group accepted")
			}
		})
	}
}

func TestParallelGroupCanQueueMoreThanTenChildren(t *testing.T) {
	input := "jobs:\n  test:\n    steps:\n      - parallel: [" + strings.Repeat("{run: echo x},", 14) + "{run: echo x}]\n"
	data, err := normalize([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	steps := field(field(field(doc.Content[0], "jobs"), "test"), "steps")
	if len(steps.Content) != 15 {
		t.Fatalf("queued parallel group lost children: %s", data)
	}
}
func TestNormalizeLeavesOrdinaryWorkflowsUnchanged(t *testing.T) {
	input := []byte("on: push\njobs:\n  test:\n    steps:\n      - run: echo unchanged\n")
	data, err := normalize(input)
	if err != nil || !bytes.Equal(data, input) {
		t.Fatalf("ordinary workflow changed: %s %v", data, err)
	}
}
func TestDSTHasFivePlatformsAndFourDisjointLanesPerRunner(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/simulation.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	jobs := field(doc.Content[0], "jobs")
	job := field(jobs, "simulation")
	matrix := field(field(job, "strategy"), "matrix")
	if len(matrix.Content) != 4 || len(field(matrix, "platform").Content) != 5 {
		t.Fatal("DST matrix must contain five platforms and explicit runner groups")
	}
	var lanes []*yaml.Node
	for _, step := range field(job, "steps").Content {
		if p := field(step, "parallel"); p != nil {
			lanes = p.Content
		}
	}
	if len(lanes) != 4 {
		t.Fatalf("expected four parallel lanes, got %d", len(lanes))
	}
	seen := map[string]bool{}
	for _, lane := range lanes {
		shard := field(field(lane, "env"), "ENBU_SIM_SHARD").Value
		if seen[shard] {
			t.Fatal("duplicate logical shard")
		}
		seen[shard] = true
		run := field(lane, "run").Value
		if !strings.Contains(run, "go test -failfast -count=1") {
			t.Fatal("lane must preserve the first failure without minimizing later failing seeds")
		}
		if !strings.Contains(run, "-parallel=1") || !strings.Contains(run, "-run \"$DST_TESTS\"") {
			t.Fatal("lane bypasses selection or nested parallelism limit")
		}
	}
	if field(field(job, "env"), "ENBU_SIM_SHARDS").Value != "${{ needs.plan.outputs.mode == 'full' && '16' || '4' }}" {
		t.Fatal("lane/shard mismatch")
	}
	schedule := field(field(doc.Content[0], "on"), "schedule")
	if field(schedule.Content[0], "cron").Value != "0 17 * * *" {
		t.Fatal("full DST must start at 02:00 Asia/Tokyo")
	}
}

func TestUbuntuRunnerPolicy(t *testing.T) {
	for _, label := range []string{"ubuntu-latest", "ubuntu-24.04", "ubuntu-24.04-arm", "ubuntu-22.04", "ubuntu-26.04-large"} {
		for _, runner := range []string{"    runs-on: ${{ github.event_name == 'push' && '" + label + "' || 'windows-2025' }}\n", "    runs-on: " + label + "\n", "    runs-on: [self-hosted, " + label + "]\n", "    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [" + label + "]\n", "    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        include:\n          - os: " + label + "\n"} {
			if _, err := normalize([]byte("jobs:\n  test:\n" + runner)); err == nil || !strings.Contains(err.Error(), label) {
				t.Errorf("accepted forbidden label: %s", runner)
			}
		}
	}
	for _, label := range []string{"ubuntu-26.04", "ubuntu-26.04-arm", "macos-15", "windows-2025", "windows-11-arm"} {
		if _, err := normalize([]byte("jobs:\n  test:\n    runs-on: " + label + "\n")); err != nil {
			t.Fatal(err)
		}
	}
}

// Every workflow still gets its own filename and normalized stdin when the
// precompiled linter is reused; an error must stop before later workflows.
func TestLintWorkflowsReusesBinaryAndPreservesFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	binary := filepath.Join(dir, "actionlint")
	script := "#!/bin/sh\ncat > /dev/null\nprintf '%s\\n' \"$*\" >> '" + calls + "'\ncase \"$*\" in *reject*) exit 7;; esac\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, name := range []string{"first.yaml", "reject.yaml", "never.yaml"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("on: push\njobs:\n  test:\n    runs-on: ubuntu-26.04\n    steps:\n      - parallel: [{run: echo one}, {run: echo two}]\n"), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	if err := lintWorkflows(paths, binary); err == nil {
		t.Fatal("linter failure was ignored")
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "first.yaml") || !strings.Contains(string(data), "reject.yaml") || strings.Contains(string(data), "never.yaml") {
		t.Fatalf("wrong workflow scheduling: %s", data)
	}
}

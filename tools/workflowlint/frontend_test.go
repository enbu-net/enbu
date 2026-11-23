package main

import (
	"strings"
	"testing"
)

func TestFrontendSetupPreventsParallelViteConfigWrites(t *testing.T) {
	setup := readYAML(t, "../../.github/actions/setup-frontend/action.yaml")
	steps := field(field(setup, "runs"), "steps").Content
	toolchain := field(steps[0], "with")
	for _, option := range []string{"node-manager", "package-manager"} {
		if field(toolchain, option).Value != "false" {
			t.Fatalf("setup must configure system-first mode for %s", option)
		}
	}
	marker := field(steps[len(steps)-1], "run").Value
	if !strings.Contains(marker, "ENBU_VP_SYSTEM_FIRST=1") || !strings.Contains(marker, "GITHUB_ENV") {
		t.Fatal("setup must mark the toolchain ready before parallel tasks run")
	}

	taskfile := readYAML(t, "../../Taskfile.yaml")
	vpEnv := field(field(taskfile, "tasks"), "vp/env")
	status := field(vpEnv, "status")
	if len(status.Content) != 1 || status.Content[0].Value != `test "${ENBU_VP_SYSTEM_FIRST:-}" = "1"` {
		t.Fatal("tasks must skip Vite+ config writes after frontend setup")
	}
}

func TestCIConfiguresViteBeforeParallelFrontendTests(t *testing.T) {
	workflow := readYAML(t, "../../.github/workflows/ci.yaml")
	job := field(field(workflow, "jobs"), "test")
	steps := field(job, "steps")
	configured := false
	pending := map[string]bool{"task gui/test": true, "task vscode/test": true}
	for _, step := range steps.Content {
		if uses := field(step, "uses"); uses != nil && uses.Value == "$/.github/actions/setup-frontend" && field(step, "if") == nil {
			configured = true
		}
		parallel := field(step, "parallel")
		if parallel == nil {
			continue
		}
		for _, child := range parallel.Content {
			run := field(child, "run")
			if run == nil {
				continue
			}
			for line := range strings.SplitSeq(run.Value, "\n") {
				command := strings.TrimSpace(line)
				if !pending[command] {
					continue
				}
				if !configured {
					t.Fatalf("%s runs without preceding unconditional frontend setup", command)
				}
				delete(pending, command)
			}
		}
	}
	if len(pending) != 0 {
		t.Fatalf("expected frontend tests in CI parallel group: %v", pending)
	}
}

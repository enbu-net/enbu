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

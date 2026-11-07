package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func statusJob(t *testing.T, file, name string) *yaml.Node {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../.github/workflows", file))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	job := field(field(doc.Content[0], "jobs"), name)
	if job == nil {
		t.Fatalf("missing status job %s in %s", name, file)
	}
	return job
}

func TestStatusJobsDoNotHoldCancelledWorkflows(t *testing.T) {
	for file, name := range map[string]string{"ci.yaml": "status-check", "simulation.yaml": "simulation-status"} {
		t.Run(file, func(t *testing.T) {
			condition := field(statusJob(t, file, name), "if")
			if condition == nil || strings.TrimSpace(condition.Value) != "${{ !cancelled() }}" {
				t.Fatal("status job must aggregate failures while remaining cancellable")
			}
		})
	}
}

func TestSimulationStatusChecksSelectedAndSkippedPlatforms(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("the workflow shell is unavailable")
	}
	job := statusJob(t, "simulation.yaml", "simulation-status")
	script := field(field(job, "steps").Content[0], "run").Value
	for _, tc := range []struct {
		name, plan, selected, result string
		ok                           bool
	}{
		{"selected-success", "success", "true", "success", true},
		{"selected-failure", "success", "true", "failure", false},
		{"selected-cancelled", "success", "true", "cancelled", false},
		{"selected-skipped", "success", "true", "skipped", false},
		{"not-selected", "success", "false", "skipped", true},
		{"unexpected-execution", "success", "false", "success", false},
		{"failed-plan", "failure", "false", "skipped", false},
		{"missing-plan", "", "false", "skipped", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), bash, "-eu", "-c", script)
			cmd.Env = append(os.Environ(), "PLAN_RESULT="+tc.plan, "SHOULD_RUN="+tc.selected, "RESULT="+tc.result)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok {
				t.Fatalf("actual status script: %v, output %s", err, out)
			}
		})
	}
}

func TestCIStatusRejectsEveryNonSuccessDependency(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("the workflow shell is unavailable")
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("the workflow JSON tool is unavailable")
	}
	job := statusJob(t, "ci.yaml", "status-check")
	script := field(field(job, "steps").Content[0], "run").Value
	for _, result := range []string{"success", "failure", "cancelled", "skipped", ""} {
		t.Run(result, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), bash, "-eu", "-o", "pipefail", "-c", script)
			cmd.Env = append(os.Environ(), `RESULTS={"passed":{"result":"success"},"other":{"result":"`+result+`"}}`)
			out, err := cmd.CombinedOutput()
			if (err == nil) != (result == "success") {
				t.Fatalf("actual status script: %v, output %s", err, out)
			}
		})
	}
}

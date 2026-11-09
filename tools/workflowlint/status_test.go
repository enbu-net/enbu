package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
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

// A skipped required check counts as passing, so a status job skipped by
// !cancelled() would let a cancelled run merge. always() makes it fail instead.
func TestStatusJobsFailCancelledWorkflows(t *testing.T) {
	for file, name := range map[string]string{"ci.yaml": "status-check", "simulation.yaml": "simulation-status", "tobari.yaml": "status-check"} {
		t.Run(file, func(t *testing.T) {
			condition := field(statusJob(t, file, name), "if")
			if condition == nil || strings.TrimSpace(condition.Value) != "always()" {
				t.Fatal("status job must run, and fail, when its workflow is cancelled")
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

func TestSimulationTimeoutLeavesRoomForMutationAndArtifacts(t *testing.T) {
	job := statusJob(t, "simulation.yaml", "simulation")
	// Read both full/incremental values from the workflow so a timeout change
	// cannot leave Go running until Actions kills the job before artifact upload.
	values := func(expression string, pattern string) []int {
		t.Helper()
		m := regexp.MustCompile(pattern).FindStringSubmatch(expression)
		if len(m) != 3 {
			t.Fatalf("unsupported timeout expression %q", expression)
		}
		out := make([]int, 2)
		for i := range out {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				t.Fatal(err)
			}
			out[i] = n
		}
		return out
	}
	jobs := values(field(job, "timeout-minutes").Value, `&& (\d+) \|\| (\d+)`)
	tests := values(field(field(job, "env"), "DST_TIMEOUT").Value, `&& '(\d+)m' \|\| '(\d+)m'`)
	for i := range jobs {
		if jobs[i] < tests[i]+20 {
			t.Fatalf("job budget %dm cannot contain %dm exploration, 15m mutations, and setup/upload", jobs[i], tests[i])
		}
	}
}

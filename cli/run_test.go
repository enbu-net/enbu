package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

// TestRunHelperProcess is the child of the run tests: it prints the variables
// named in ENBU_TEST_PRINT and exits with ENBU_TEST_EXIT.
func TestRunHelperProcess(t *testing.T) {
	if os.Getenv("ENBU_TEST_HELPER") != "1" {
		return
	}
	for _, name := range strings.Split(os.Getenv("ENBU_TEST_PRINT"), ",") {
		fmt.Printf("%s=%s\n", name, os.Getenv(name))
	}
	code := 0
	if _, err := fmt.Sscan(os.Getenv("ENBU_TEST_EXIT"), &code); err != nil {
		code = 0
	}
	os.Exit(code)
}

func helperCommand() []string {
	return []string{os.Args[0], "-test.run=^TestRunHelperProcess$"}
}

func runWith(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		t.Setenv(k, v)
	}
	a, _ := newSeededApp(t, map[string]string{"KEY": "from-enbu", "OTHER": "o"})
	cmd := NewWithApp("test", a)
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestRunInjectsSecretsIntoTheCommand(t *testing.T) {
	out, err := runWith(t, []string{"ENBU_TEST_HELPER=1", "ENBU_TEST_PRINT=KEY,OTHER", "KEY=from-shell"},
		append([]string{"run", "--no-masking", "--"}, helperCommand()...)...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "KEY=from-enbu\n") || !strings.Contains(out, "OTHER=o\n") {
		t.Fatalf("output:\n%s", out)
	}
}

// Output that is not a terminal has the secret values concealed; values too
// short to mask, and values that came from the shell, pass through.
func TestRunMasksSecretsInOutput(t *testing.T) {
	out, err := runWith(t, []string{"ENBU_TEST_HELPER=1", "ENBU_TEST_PRINT=KEY,OTHER"},
		append([]string{"run", "--"}, helperCommand()...)...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "from-enbu") || !strings.Contains(out, "KEY=<concealed by enbu>\n") || !strings.Contains(out, "OTHER=o\n") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestRunPreserveEnvKeepsShellValues(t *testing.T) {
	out, err := runWith(t, []string{"ENBU_TEST_HELPER=1", "ENBU_TEST_PRINT=KEY,OTHER", "KEY=from-shell"},
		append([]string{"run", "--preserve-env", "--"}, helperCommand()...)...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "KEY=from-shell\n") || !strings.Contains(out, "OTHER=o\n") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestRunPropagatesTheExitCode(t *testing.T) {
	_, err := runWith(t, []string{"ENBU_TEST_HELPER=1", "ENBU_TEST_PRINT=KEY", "ENBU_TEST_EXIT=7"},
		append([]string{"run", "--"}, helperCommand()...)...)
	var exit *apperr.ExitError
	if !errors.As(err, &exit) || exit.Code != 7 || apperr.ExitCode(err) != 7 {
		t.Fatalf("err = %v, exit code %d", err, apperr.ExitCode(err))
	}
}

func TestRunRefusesJSONAndNeedsACommand(t *testing.T) {
	if _, err := runWith(t, nil, "run", "--json", "--", "true"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("--json accepted: %v", err)
	}
	if _, err := runWith(t, nil, "run"); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("no command accepted: %v", err)
	}
}

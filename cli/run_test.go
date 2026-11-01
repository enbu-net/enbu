package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
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

func TestMergeEnvKeepsHiddenDriveVariables(t *testing.T) {
	base := []string{`=C:=C:\work`, `=D:=D:\data`, "=ExitCode=00000000", "HOME=/h"}
	got := mergeEnv(base, map[string]string{"KEY": "v"}, false, true)
	want := []string{`=C:=C:\work`, `=D:=D:\data`, "=ExitCode=00000000", "HOME=/h", "KEY=v"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeEnv = %q, want %q", got, want)
	}
}

func TestMergeEnvFoldsCaseWhenAsked(t *testing.T) {
	base := []string{`Path=C:\Windows`, "keep=shell"}
	secrets := map[string]string{"PATH": `C:\tools`, "KEEP": "secret"}
	if got, want := mergeEnv(base, secrets, false, true), []string{`KEEP=secret`, `PATH=C:\tools`}; !reflect.DeepEqual(got, want) {
		t.Fatalf("secrets win: got %q, want %q", got, want)
	}
	if got, want := mergeEnv(base, secrets, true, true), []string{`Path=C:\Windows`, "keep=shell"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("preserve: got %q, want %q", got, want)
	}
	if got := mergeEnv(base, secrets, false, false); len(got) != 4 {
		t.Fatalf("case-sensitive merge = %q, want 4 variables", got)
	}
}

func TestCutEnv(t *testing.T) {
	for _, tt := range []struct {
		kv, name, value string
		ok              bool
	}{
		{"A=b", "A", "b", true},
		{"A=b=c", "A", "b=c", true},
		{"A=", "A", "", true},
		{`=C:=C:\x`, "=C:", `C:\x`, true},
		{"noequals", "", "", false},
		{"=", "", "", false},
		{"", "", "", false},
	} {
		name, value, ok := cutEnv(tt.kv)
		if name != tt.name || value != tt.value || ok != tt.ok {
			t.Errorf("cutEnv(%q) = %q, %q, %v; want %q, %q, %v", tt.kv, name, value, ok, tt.name, tt.value, tt.ok)
		}
	}
}

func TestMergeEnvFoldedSecretsAreDeterministic(t *testing.T) {
	secrets := map[string]string{"Foo": "a", "FOO": "b", "foo": "c"}
	first := mergeEnv(nil, secrets, false, true)
	for range 50 {
		if got := mergeEnv(nil, secrets, false, true); !reflect.DeepEqual(got, first) {
			t.Fatalf("mergeEnv = %q, then %q", first, got)
		}
	}
	if want := []string{"foo=c"}; !reflect.DeepEqual(first, want) {
		t.Fatalf("mergeEnv = %q, want %q (the last name in sorted order wins)", first, want)
	}
}

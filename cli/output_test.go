package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/internal/application"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/spf13/cobra"
)

func TestJSONMetadataCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		key  string
		want string
	}{
		{name: "root", args: []string{"--json"}, key: "command", want: "enbu"},
		{name: "root help", args: []string{"--help", "--json"}, key: "command", want: "enbu"},
		{name: "auth help", args: []string{"auth", "--json"}, key: "command", want: "enbu auth"},
		{name: "history help", args: []string{"history", "--json"}, key: "command", want: "enbu history"},
		{name: "help command", args: []string{"help", "add", "--json"}, key: "command", want: "enbu add"},
		{name: "version", args: []string{"--version", "--json"}, key: "version", want: "test-version"},
		{name: "completion", args: []string{"completion", "bash", "--json"}, key: "shell", want: "bash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := executeJSON(t, NewWithApp("test-version", &app.App{}), tt.args...)
			data := objectField(t, envelope, "data")
			if got := stringField(t, data, tt.key); got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestJSONExecutionErrorsUseOneStdoutObject(t *testing.T) {
	tests := [][]string{
		{"unknown", "--json"},
		{"--unknown", "--json"},
		{"--json=invalid"},
		{"add", "--json"},
		{"pull", "--json", "--stdout"},
	}

	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			envelope, err := executeJSONResult(t, NewWithApp("test", &app.App{}), args...)
			if err == nil {
				t.Fatal("execution unexpectedly succeeded")
			}
			if ok, _ := envelope["ok"].(bool); ok {
				t.Fatalf("response unexpectedly succeeded: %#v", envelope)
			}
			errorData := objectField(t, envelope, "error")
			if stringField(t, errorData, "message") == "" {
				t.Fatal("empty error message")
			}
			if stringField(t, errorData, "code") == "" {
				t.Fatal("empty error code")
			}
			if _, ok := errorData["params"].(map[string]any); !ok {
				t.Fatalf("params = %#v, want object", errorData["params"])
			}
		})
	}
}

func TestRenderExecutionErrorHonorsOptionTerminator(t *testing.T) {
	cmd := NewWithApp("test", &app.App{})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	RenderExecutionError(cmd, errors.New("failed"), []string{"add", "KEY", "--", "--json"})

	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if got := stderr.String(); got != "Error: An unexpected error occurred.\n" {
		t.Fatalf("stderr = %q", got)
	}
}

func TestRenderExecutionErrorSkipsOptionValues(t *testing.T) {
	cmd := NewWithApp("test", &app.App{})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)

	// --env consumes the next argument as its value; --json is that value, not a flag
	RenderExecutionError(cmd, errors.New("failed"), []string{"add", "KEY", "VALUE", "--env", "--json"})

	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty (--json was a value for --env, not a flag)", stdout.String())
	}
	if got := stderr.String(); got != "Error: An unexpected error occurred.\n" {
		t.Fatalf("stderr = %q", got)
	}
}

func TestJSONUserInputErrorsAreInvalidArguments(t *testing.T) {
	tests := [][]string{
		{"history", "diff", "nope", "1", "--json"},
		{"history", "restore", "nope", "--json"},
		{"completion", "nope", "--json"},
		{"switch", "--delete", "--json"},
		{"switch", "--move", "old", "--json"},
		{"pull", "--stdout", "--json"},
		{"auth", "login", "--device", "--json"},
	}

	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			envelope, err := executeJSONResult(t, NewWithApp("test", &app.App{}), args...)
			if !apperr.Is(err, apperr.CodeInvalidArgument) {
				t.Fatalf("error = %v, want invalid_argument", err)
			}
			if got := apperr.ExitCode(err); got != 2 {
				t.Fatalf("exit code = %d, want 2", got)
			}
			errorData := objectField(t, envelope, "error")
			if got := stringField(t, errorData, "code"); got != string(apperr.CodeInvalidArgument) {
				t.Fatalf("code = %q, want %q", got, apperr.CodeInvalidArgument)
			}
		})
	}
}

func TestCompletionNoDescriptions(t *testing.T) {
	generate := func(t *testing.T, shell string, noDescriptions bool) string {
		t.Helper()
		cmd := NewWithApp("test", &app.App{})
		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		args := []string{"completion", shell}
		if noDescriptions {
			args = append(args, "--no-descriptions")
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("completion %s: %v", shell, err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("completion %s stderr = %q", shell, stderr.String())
		}
		if stdout.Len() == 0 {
			t.Fatalf("completion %s produced no output", shell)
		}
		return stdout.String()
	}

	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			withDescriptions := generate(t, shell, false)
			withoutDescriptions := generate(t, shell, true)
			if withDescriptions == withoutDescriptions {
				t.Fatalf("completion %s ignored --no-descriptions", shell)
			}
		})
	}
}

func TestJSONAuthLoginEmitsOnlyFinalResult(t *testing.T) {
	login := newAuthLoginCommandWithDeps(authLoginDeps{
		browserLogin: func(_ context.Context, open auth.BrowserOpener) (*auth.StoredToken, error) {
			if err := open("https://github.com/login/oauth/authorize"); err != nil {
				return nil, err
			}
			return &auth.StoredToken{Username: "octo"}, nil
		},
		openBrowser: func(string) error { return nil },
	})
	root := jsonTestRoot(login)
	envelope := executeJSON(t, root, "login", "--json")
	data := objectField(t, envelope, "data")
	if got := stringField(t, data, "username"); got != "octo" {
		t.Fatalf("username = %q", got)
	}
}

func TestJSONAuthDeviceIsRejectedBeforeLogin(t *testing.T) {
	called := false
	login := newAuthLoginCommandWithDeps(authLoginDeps{
		deviceLogin: func(context.Context, string, auth.DevicePrompter) (*auth.StoredToken, error) {
			called = true
			return nil, errors.New("unexpected call")
		},
	})
	envelope, err := executeJSONResult(t, jsonTestRoot(login), "login", "--device", "--json")
	if err == nil {
		t.Fatal("execution unexpectedly succeeded")
	}
	if called {
		t.Fatal("device login started before rejecting JSON mode")
	}
	if ok, _ := envelope["ok"].(bool); ok {
		t.Fatalf("response unexpectedly succeeded: %#v", envelope)
	}
}

func TestJSONAuthLogout(t *testing.T) {
	called := false
	logout := newAuthLogoutCommandWithDelete(func() error {
		called = true
		return nil
	})
	envelope := executeJSON(t, jsonTestRoot(logout), "logout", "--json")
	if !called {
		t.Fatal("token delete was not called")
	}
	data := objectField(t, envelope, "data")
	if loggedOut, _ := data["logged_out"].(bool); !loggedOut {
		t.Fatalf("logged_out = %#v", data["logged_out"])
	}
}

func TestJSONAuthStatus(t *testing.T) {
	enterTempRepository(t)
	keyPair, err := age.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	a := &app.App{RepoDetector: &deleteTestRepoDetector{}}
	status := newAuthStatusCommandWithDeps(a, authStatusDeps{
		loadToken: func() (*auth.StoredToken, error) {
			return &auth.StoredToken{Username: "octo"}, nil
		},
		newKeyStore: func() (app.KeyStore, error) {
			return &staticKeyStore{key: []byte(keyPair.Identity.String())}, nil
		},
	})
	envelope := executeJSON(t, jsonTestRoot(status), "status", "--json")
	data := objectField(t, envelope, "data")
	if authenticated, _ := data["authenticated"].(bool); !authenticated {
		t.Fatalf("authenticated = %#v", data["authenticated"])
	}
	if got := stringField(t, data, "username"); got != "octo" {
		t.Fatalf("username = %q", got)
	}
}

func TestEncodeJSONEscapesAsJSONWithoutHTMLEscaping(t *testing.T) {
	var output bytes.Buffer
	if err := encodeJSON(&output, successEnvelope{
		OK:       true,
		Data:     map[string]string{"value": "<tag>\n\"quoted\""},
		Warnings: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), `\u003c`) {
		t.Fatalf("HTML escaped output: %s", output.String())
	}
	assertOneJSONObject(t, output.String())
}

func jsonTestRoot(commands ...*cobra.Command) *cobra.Command {
	root := &cobra.Command{Use: "enbu", SilenceErrors: true, SilenceUsage: true}
	root.PersistentFlags().Bool("json", false, "Output one JSON response")
	root.AddCommand(commands...)
	return root
}

func executeJSON(t *testing.T, cmd *cobra.Command, args ...string) map[string]any {
	t.Helper()
	result, err := executeJSONResult(t, cmd, args...)
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}
	return result
}

func executeJSONResult(t *testing.T, cmd *cobra.Command, args ...string) (map[string]any, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	if err != nil {
		RenderExecutionError(cmd, err, args)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
	result := assertOneJSONObject(t, stdout.String())
	if ok, _ := result["ok"].(bool); ok {
		warnings, valid := result["warnings"].([]any)
		if !valid || warnings == nil {
			t.Fatalf("warnings = %#v, want an array", result["warnings"])
		}
	}
	return result, err
}

func assertOneJSONObject(t *testing.T, output string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(output))
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("invalid JSON %q: %v", output, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("output contains more than one JSON value: %q", output)
	}
	return result
}

func objectField(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want object", key, object[key])
	}
	return value
}

func stringField(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok {
		t.Fatalf("%s is %T, want string", key, object[key])
	}
	return value
}

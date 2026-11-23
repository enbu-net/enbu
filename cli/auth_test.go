package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/auth"
)

func deviceLogin(t *testing.T) func(context.Context, auth.DevicePrompter) (*auth.StoredToken, error) {
	return func(_ context.Context, prompt auth.DevicePrompter) (*auth.StoredToken, error) {
		if err := prompt(auth.DeviceAuthorization{UserCode: "ABCD-1234", VerificationURI: "https://github.com/login/device"}); err != nil {
			t.Fatal(err)
		}
		return &auth.StoredToken{Username: "octo"}, nil
	}
}

func TestAuthLoginShowsTheDeviceCode(t *testing.T) {
	for _, args := range [][]string{{"login"}, {"login", "--json"}} {
		var opened string
		cmd := jsonTestRoot(newAuthLoginCommandWithDeps(authLoginDeps{login: deviceLogin(t), openBrowser: func(uri string) error { opened = uri; return nil }}))
		var stdout, stderr bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(&stderr)
		cmd.SetArgs(args)
		if err := cmd.ExecuteContext(context.Background()); err != nil {
			t.Fatalf("ExecuteContext: %v", err)
		}
		if opened != "https://github.com/login/device" {
			t.Fatalf("opened URL = %q", opened)
		}
		if !strings.Contains(stderr.String(), "Enter the code ABCD-1234 at https://github.com/login/device") {
			t.Fatalf("stderr = %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "octo") {
			t.Fatalf("stdout = %q", stdout.String())
		}
	}
}

func TestAuthLoginOpenFailureUsesManualMessage(t *testing.T) {
	cmd := newAuthLoginCommandWithDeps(authLoginDeps{login: deviceLogin(t), openBrowser: func(string) error { return errors.New("headless") }})
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext: %v", err)
	}
	if !strings.Contains(output.String(), "Could not open the browser automatically") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestAuthSwitchUsesTheNamedAccount(t *testing.T) {
	var asked string
	cmd := newAuthSwitchCommandWithDeps(func(login string) (*auth.StoredToken, error) {
		asked = login
		return &auth.StoredToken{Username: "octo-work"}, nil
	})
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"octo-work"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext: %v", err)
	}
	if asked != "octo-work" || !strings.Contains(output.String(), "Using GitHub account: octo-work") {
		t.Fatalf("switched to %q, output %q", asked, output.String())
	}

	cmd = newAuthSwitchCommandWithDeps(func(string) (*auth.StoredToken, error) {
		t.Fatal("switch without a login should not reach the store")
		return nil, nil
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(nil)
	if err := cmd.ExecuteContext(context.Background()); err == nil {
		t.Fatal("switch without a login succeeded")
	}
}

func TestAuthLogoutUserSignsOutOfThatAccount(t *testing.T) {
	var removed string
	cmd := newAuthLogoutCommandWithDelete(func(login string) error {
		removed = login
		return nil
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--user", "octo-work"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext: %v", err)
	}
	if removed != "octo-work" {
		t.Fatalf("signed out of %q, want octo-work", removed)
	}
}

func TestAuthLoginUsesEnvironmentWithoutDeviceFlow(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ephemeral-test-token")
	t.Setenv("GITHUB_ACTOR", "ci-test-user")
	cmd := newAuthLoginCommandWithDeps(authLoginDeps{})
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "ci-test-user") || strings.Contains(output.String(), "ephemeral-test-token") {
		t.Fatalf("unexpected login output: %q", output.String())
	}
}

func TestAuthResetRequiresConfirmation(t *testing.T) {
	cmd := newAuthMaintenanceCommand(true)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("reset without confirmation = %v", err)
	}
}

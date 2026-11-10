package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/spf13/cobra"
)

func TestAuthLoginDeviceFlagUsesDeviceFlow(t *testing.T) {
	var opened string
	deps := authLoginDeps{
		browserLogin: func(context.Context, auth.BrowserOpener) (*auth.StoredToken, error) {
			return nil, errors.New("browser login should not be called")
		},
		deviceLogin: func(
			_ context.Context,
			clientID string,
			prompt auth.DevicePrompter,
		) (*auth.StoredToken, error) {
			if clientID != defaultDeviceClientID {
				t.Fatalf("client ID = %q", clientID)
			}
			if err := prompt(auth.DeviceAuthorization{
				UserCode:        "ABCD-1234",
				VerificationURI: "https://github.com/login/device",
			}); err != nil {
				t.Fatal(err)
			}
			return &auth.StoredToken{Username: "octo"}, nil
		},
		openBrowser: func(uri string) error {
			opened = uri
			return nil
		},
	}
	cmd := newAuthLoginCommandWithDeps(deps)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--device"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext: %v", err)
	}
	if opened != "https://github.com/login/device" {
		t.Fatalf("opened URL = %q", opened)
	}
	for _, want := range []string{
		"ABCD-1234",
		"Verification URL: https://github.com/login/device",
		"Opened in your browser",
		"Waiting for authorization",
		"Authenticated as: octo",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output %q does not contain %q", output.String(), want)
		}
	}
}

func TestAuthLoginDefaultsToCodeFlow(t *testing.T) {
	var opened string
	var output bytes.Buffer
	deps := authLoginDeps{
		browserLogin: func(_ context.Context, open auth.BrowserOpener) (*auth.StoredToken, error) {
			if err := open("https://github.com/login/oauth/authorize"); err != nil {
				return nil, err
			}
			return &auth.StoredToken{Username: "octo"}, nil
		},
		deviceLogin: func(context.Context, string, auth.DevicePrompter) (*auth.StoredToken, error) {
			return nil, errors.New("device login should not be called")
		},
		openBrowser: func(uri string) error {
			opened = uri
			return nil
		},
	}
	cmd := newAuthLoginCommandWithDeps(deps)
	cmd.SetOut(&output)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext: %v", err)
	}
	if opened != "https://github.com/login/oauth/authorize" {
		t.Fatalf("opened URL = %q", opened)
	}
	if !strings.Contains(output.String(), "Opened GitHub in your browser") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestAuthLoginDeviceOpenFailureUsesManualMessage(t *testing.T) {
	deps := authLoginDeps{
		deviceLogin: func(
			_ context.Context,
			_ string,
			prompt auth.DevicePrompter,
		) (*auth.StoredToken, error) {
			if err := prompt(auth.DeviceAuthorization{
				UserCode:        "ABCD-1234",
				VerificationURI: "https://github.com/login/device",
			}); err != nil {
				return nil, err
			}
			return &auth.StoredToken{Username: "octo"}, nil
		},
		openBrowser: func(string) error { return errors.New("headless") },
	}
	cmd := newAuthLoginCommandWithDeps(deps)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--device"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext: %v", err)
	}
	if !strings.Contains(output.String(), "Could not open the browser automatically") ||
		strings.Contains(output.String(), "Opened in your browser") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestAuthLoginDeviceUsesClientIDOverride(t *testing.T) {
	t.Setenv("ENBU_CLIENT_ID", "custom-client-id")
	deps := authLoginDeps{
		deviceLogin: func(
			_ context.Context,
			clientID string,
			_ auth.DevicePrompter,
		) (*auth.StoredToken, error) {
			if clientID != "custom-client-id" {
				t.Fatalf("client ID = %q", clientID)
			}
			return &auth.StoredToken{Username: "octo"}, nil
		},
	}
	cmd := newAuthLoginCommandWithDeps(deps)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--device"})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext: %v", err)
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

// Inside WSL the Windows enbu.exe signs in; this data directory then uses
// that account, and a failed Windows login changes nothing.
func TestAuthLoginInWSLUsesTheNewAccount(t *testing.T) {
	for _, windowsErr := range []error{nil, errors.New("windows login failed")} {
		used := false
		cmd := newAuthLoginCommandWithDeps(authLoginDeps{
			windows:   func(context.Context, *cobra.Command, ...string) error { return windowsErr },
			useLatest: func() error { used = true; return nil },
		})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(nil)
		err := cmd.ExecuteContext(context.Background())
		if (err != nil) != (windowsErr != nil) || used != (windowsErr == nil) {
			t.Fatalf("windows error %v: login = %v, used latest = %v", windowsErr, err, used)
		}
	}
}

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/auth"
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

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

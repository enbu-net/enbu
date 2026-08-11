package cli

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/enbu-net/enbu/internal/apphost"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
)

func TestVersionAndBreakingCommandSurface(t *testing.T) {
	command := newCommand("v1.2.3", func(context.Context) (*apphost.Runtime, apphost.ProductionIdentity, error) {
		t.Fatal("version must not initialize runtime")
		return nil, apphost.ProductionIdentity{}, nil
	})
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"version"})
	if err := command.Execute(); err != nil || output.String() != "v1.2.3\n" {
		t.Fatalf("version = %q, %v", output.String(), err)
	}
	names := make([]string, 0, len(command.Commands()))
	for _, child := range command.Commands() {
		names = append(names, child.Name())
	}
	for _, forbidden := range []string{"add", "edit", "delete", "pull", "sync", "switch"} {
		for _, name := range names {
			if reflect.DeepEqual(name, forbidden) {
				t.Fatalf("legacy command %q remains", forbidden)
			}
		}
	}
}

func TestAuthStatusDoesNotExposeCredentials(t *testing.T) {
	jsonOutput := true
	command := newAuthCommand(&jsonOutput, authDependencies{
		loadToken: func() (*auth.StoredToken, error) {
			return &auth.StoredToken{AccessToken: "must-not-appear", Username: "octocat", UserID: 1}, nil
		},
	})
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"status"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "{\"authenticated\":true,\"username\":\"octocat\"}\n" {
		t.Fatalf("status = %q", got)
	}
}

func TestAuthStatusReportsLoggedOutWithoutFailing(t *testing.T) {
	jsonOutput := true
	command := newAuthCommand(&jsonOutput, authDependencies{
		loadToken: func() (*auth.StoredToken, error) {
			return nil, apperr.New(apperr.CodeNotAuthenticated, "not logged in", nil)
		},
	})
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"status"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "{\"authenticated\":false}\n" {
		t.Fatalf("status = %q", got)
	}
}

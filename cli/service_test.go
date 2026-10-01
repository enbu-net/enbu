package cli

import (
	"strings"
	"testing"

	"github.com/enbu-net/enbu/app"
)

func TestDefaultAppWithInvalidBackendReturnsKeystoreError(t *testing.T) {
	t.Setenv("ENBU_IDENTITY_BACKEND", "invalid")

	a := app.New()
	_, err := app.LoadIdentitiesForRepo(a.Identities, "owner", "repo")
	if err == nil {
		t.Fatal("expected keystore initialization error")
	}
	if !strings.Contains(err.Error(), "invalid ENBU_IDENTITY_BACKEND") {
		t.Fatalf("expected invalid ENBU_IDENTITY_BACKEND error, got %v", err)
	}
}

func TestLoadIdentitiesForRepoWithNilKeyStore(t *testing.T) {
	_, err := app.LoadIdentitiesForRepo(nil, "owner", "repo")
	if err == nil {
		t.Fatal("expected error for nil keystore")
	}
	if !strings.Contains(err.Error(), "identity store is not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

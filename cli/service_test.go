//go:build legacy

package cli

import (
	"strings"
	"testing"

	"github.com/enbu-net/enbu/internal/application"
)

func TestDefaultAppWithInvalidBackendReturnsKeystoreError(t *testing.T) {
	t.Setenv("ENBU_BACKEND", "invalid")

	a := app.New()
	_, err := app.LoadIdentitiesForRepo(a.KeyStore, "owner", "repo")
	if err == nil {
		t.Fatal("expected keystore initialization error")
	}
	if !strings.Contains(err.Error(), "unknown backend type") {
		t.Fatalf("expected unknown backend type error, got %v", err)
	}
}

func TestLoadIdentitiesForRepoWithNilKeyStore(t *testing.T) {
	_, err := app.LoadIdentitiesForRepo(nil, "owner", "repo")
	if err == nil {
		t.Fatal("expected error for nil keystore")
	}
	if !strings.Contains(err.Error(), "keystore is not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

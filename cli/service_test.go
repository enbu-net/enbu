package cli

import (
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/clock"

	"github.com/enbu-net/enbu/app"
)

func TestDefaultAppWithInvalidBackendReturnsKeystoreError(t *testing.T) {
	t.Setenv("ENBU_IDENTITY_BACKEND", "invalid")

	a := app.New(clock.New())
	_, err := a.Identities.Load("owner/repo")
	if err == nil {
		t.Fatal("expected keystore initialization error")
	}
	if !strings.Contains(err.Error(), "invalid ENBU_IDENTITY_BACKEND") {
		t.Fatalf("expected invalid ENBU_IDENTITY_BACKEND error, got %v", err)
	}
}

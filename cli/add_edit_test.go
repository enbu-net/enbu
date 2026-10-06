package cli

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func secretsOf(t *testing.T, a interface {
	ListSecrets(context.Context, string) (map[string]string, error)
}) map[string]string {
	t.Helper()
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestAddCommandRejectsExistingSecret(t *testing.T) {
	a, rec := newSeededApp(t, map[string]string{"API_KEY": "old"})
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"add", "API_KEY", "new"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected duplicate add to fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	if got := rec.secretPuts(); len(got) != 0 {
		t.Fatalf("expected duplicate add not to push, got %d pushes", len(got))
	}
}

func TestAddCommandCreatesNewSecret(t *testing.T) {
	a, rec := newSeededApp(t, nil)
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"add", "API_KEY", "secret"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("add: %v", err)
	}
	puts := rec.secretPuts()
	if len(puts) != 2 {
		t.Fatalf("expected 2 push (main + snapshot), got %d", len(puts))
	}
	if puts[0].expected != "" {
		t.Fatalf("expected empty base version for initial add, got %q", puts[0].expected)
	}
	if got := secretsOf(t, a); !reflect.DeepEqual(got, map[string]string{"API_KEY": "secret"}) {
		t.Fatalf("secrets = %v", got)
	}
}

func TestEditCommandUpdatesExistingSecret(t *testing.T) {
	a, rec := newSeededApp(t, map[string]string{"API_KEY": "old"})
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"edit", "API_KEY", "new"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("edit: %v", err)
	}
	puts := rec.secretPuts()
	if len(puts) != 2 {
		t.Fatalf("expected 2 push (main + snapshot), got %d", len(puts))
	}
	if puts[0].expected == "" || puts[0].expected != puts[0].lastRead {
		t.Fatalf("push must be based on the version that was read: expected=%q read=%q", puts[0].expected, puts[0].lastRead)
	}
	if got := secretsOf(t, a); got["API_KEY"] != "new" {
		t.Fatalf("API_KEY = %q", got["API_KEY"])
	}
}

func TestEditCommandRejectsMissingSecret(t *testing.T) {
	a, rec := newSeededApp(t, map[string]string{"OTHER": "value"})
	cmd := NewWithApp("test", a)
	cmd.SetArgs([]string{"edit", "API_KEY", "secret"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected missing edit to fail")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing error, got %v", err)
	}
	if got := rec.secretPuts(); len(got) != 0 {
		t.Fatalf("expected missing edit not to push, got %d pushes", len(got))
	}
}

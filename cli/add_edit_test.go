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
	if len(puts) != 1 {
		t.Fatalf("expected 1 publish, got %d", len(puts))
	}
	if len(puts[0].parents) != 0 {
		t.Fatalf("the first revision has no parents, got %v", puts[0].parents)
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
	if len(puts) != 1 {
		t.Fatalf("expected 1 publish, got %d", len(puts))
	}
	if len(puts[0].parents) != 1 {
		t.Fatalf("the revision must be based on the one that was read: parents=%v", puts[0].parents)
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

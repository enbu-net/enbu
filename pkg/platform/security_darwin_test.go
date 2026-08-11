//go:build darwin

package platform

import (
	"path/filepath"
	"testing"
)

func TestCanonicalizeParentPathResolvesOnlySystemOwnedParentAliases(t *testing.T) {
	parentAlias := filepath.Join(string(filepath.Separator), "var", "folders", "enbu", "artifact")
	got, err := CanonicalizeParentPath(parentAlias)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(string(filepath.Separator), "private", "var", "folders", "enbu", "artifact")
	if got != want {
		t.Fatalf("canonical path = %q, want %q", got, want)
	}

	finalAlias := filepath.Join(string(filepath.Separator), "var")
	got, err = CanonicalizeParentPath(finalAlias)
	if err != nil {
		t.Fatal(err)
	}
	if got != finalAlias {
		t.Fatalf("final component was resolved: got %q, want %q", got, finalAlias)
	}
}

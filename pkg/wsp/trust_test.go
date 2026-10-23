package wsp

import (
	"errors"
	"os"
	"testing"

	digest "github.com/opencontainers/go-digest"
)

func TestTrustRootPinsTheFirstGenesis(t *testing.T) {
	dir := t.TempDir()
	g1, g2 := digest.FromString("g1"), digest.FromString("g2")
	tr := OpenTrustRoot(dir, "ws")
	if err := tr.Check(g1); err != nil {
		t.Fatalf("nothing pinned yet: %v", err)
	}
	if prev, err := tr.Pin(g1, false); err != nil || prev != "" {
		t.Fatalf("first pin: %q %v", prev, err)
	}
	if prev, err := tr.Pin(g1, false); err != nil || prev != g1 {
		t.Fatalf("pinning the same genesis again: %q %v", prev, err)
	}
	// A fresh handle reads the pin back from disk.
	tr = OpenTrustRoot(dir, "ws")
	var changed *TrustRootChangedError
	if err := tr.Check(g2); !errors.As(err, &changed) || changed.Pinned != g1 || changed.Configured != g2 {
		t.Fatalf("Check accepted another genesis: %v", err)
	}
	if _, err := tr.Pin(g2, false); !errors.As(err, &changed) {
		t.Fatalf("Pin replaced the genesis without replace: %v", err)
	}
	if got, _ := tr.Pinned(); got != g1 {
		t.Fatalf("pin changed to %s", got)
	}
	if prev, err := tr.Pin(g2, true); err != nil || prev != g1 {
		t.Fatalf("replace: %q %v", prev, err)
	}
	if err := tr.Check(g2); err != nil {
		t.Fatalf("replaced genesis rejected: %v", err)
	}
}

func TestTrustRootIsPerWorkspace(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenTrustRoot(dir, "a").Pin(digest.FromString("g1"), false); err != nil {
		t.Fatal(err)
	}
	if err := OpenTrustRoot(dir, "b").Check(digest.FromString("g2")); err != nil {
		t.Fatalf("a pin leaked to another workspace: %v", err)
	}
}

func TestTrustRootRejectsACorruptFileUnlessReplaced(t *testing.T) {
	dir := t.TempDir()
	tr := OpenTrustRoot(dir, "ws")
	if err := os.WriteFile(tr.path, []byte(`{"version":1,"genesis":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tr.Check(digest.FromString("g")); err == nil {
		t.Fatal("a corrupt pin was accepted")
	}
	if _, err := tr.Pin(digest.FromString("g"), false); err == nil {
		t.Fatal("a corrupt pin was overwritten without replace")
	}
	if _, err := tr.Pin(digest.FromString("g"), true); err != nil {
		t.Fatalf("replace could not repair a corrupt pin: %v", err)
	}
}

func TestTrustRootRejectsAnInvalidDigest(t *testing.T) {
	if _, err := OpenTrustRoot(t.TempDir(), "ws").Pin("sha256:short", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pinned an invalid digest: %v", err)
	}
}

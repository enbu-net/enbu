package wsp

import (
	"errors"
	"os"
	"testing"

	digest "github.com/opencontainers/go-digest"
)

func root(ws, g string) Root { return Root{Workspace: ws, Genesis: digest.FromString(g)} }

func TestTrustRootPinsTheFirstRoot(t *testing.T) {
	dir := t.TempDir()
	r1, r2 := root("ws", "g1"), root("ws", "g2")
	tr := OpenTrustRoot(dir, "ws")
	if err := tr.Check(r1); err != nil {
		t.Fatalf("nothing pinned yet: %v", err)
	}
	if prev, err := tr.Pin(r1, false); err != nil || prev != (Root{}) {
		t.Fatalf("first pin: %v %v", prev, err)
	}
	if prev, err := tr.Pin(r1, false); err != nil || prev != r1 {
		t.Fatalf("pinning the same root again: %v %v", prev, err)
	}
	// A fresh handle reads the pin back from disk.
	tr = OpenTrustRoot(dir, "ws")
	var changed *TrustRootChangedError
	if err := tr.Check(r2); !errors.As(err, &changed) || changed.Pinned != r1 || changed.Configured != r2 {
		t.Fatalf("Check accepted another genesis: %v", err)
	}
	if _, err := tr.Pin(r2, false); !errors.As(err, &changed) {
		t.Fatalf("Pin replaced the root without replace: %v", err)
	}
	if got, _ := tr.Pinned(); got != r1 {
		t.Fatalf("pin changed to %v", got)
	}
	if prev, err := tr.Pin(r2, true); err != nil || prev != r1 {
		t.Fatalf("replace: %v %v", prev, err)
	}
	if err := tr.Check(r2); err != nil {
		t.Fatalf("replaced root rejected: %v", err)
	}
}

// The repository pin compares the workspace too, so changing both fields of
// enbu.toml is still a change of trust root.
func TestRepositoryTrustRootComparesTheWorkspace(t *testing.T) {
	dir := t.TempDir()
	tr := OpenRepositoryTrustRoot(dir, "/repo/enbu.toml")
	if _, err := tr.Pin(root("ws1", "g1"), false); err != nil {
		t.Fatal(err)
	}
	var changed *TrustRootChangedError
	if err := tr.Check(root("ws2", "g2")); !errors.As(err, &changed) || changed.Pinned.Workspace != "ws1" {
		t.Fatalf("another workspace was accepted: %v", err)
	}
	if err := OpenRepositoryTrustRoot(dir, "/other/enbu.toml").Check(root("ws2", "g2")); err != nil {
		t.Fatalf("a pin leaked to another repository: %v", err)
	}
}

func TestTrustRootIsPerWorkspace(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenTrustRoot(dir, "a").Pin(root("a", "g1"), false); err != nil {
		t.Fatal(err)
	}
	if err := OpenTrustRoot(dir, "b").Check(root("b", "g2")); err != nil {
		t.Fatalf("a pin leaked to another workspace: %v", err)
	}
}

func TestTrustRootRejectsACorruptFileUnlessReplaced(t *testing.T) {
	dir := t.TempDir()
	tr := OpenTrustRoot(dir, "ws")
	if err := os.WriteFile(tr.path, []byte(`{"version":1,"workspace":"ws","genesis":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tr.Check(root("ws", "g")); err == nil {
		t.Fatal("a corrupt pin was accepted")
	}
	if _, err := tr.Pin(root("ws", "g"), false); err == nil {
		t.Fatal("a corrupt pin was overwritten without replace")
	}
	if _, err := tr.Pin(root("ws", "g"), true); err != nil {
		t.Fatalf("replace could not repair a corrupt pin: %v", err)
	}
}

func TestTrustRootRejectsAnInvalidRoot(t *testing.T) {
	tr := OpenTrustRoot(t.TempDir(), "ws")
	if _, err := tr.Pin(Root{Workspace: "ws", Genesis: "sha256:short"}, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pinned an invalid digest: %v", err)
	}
	if _, err := tr.Pin(Root{Genesis: digest.FromString("g")}, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pinned a root without a workspace: %v", err)
	}
}

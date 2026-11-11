package wsp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/clock"
	digest "github.com/opencontainers/go-digest"
)

func root(ws, g string) Root { return Root{Workspace: ws, Genesis: digest.FromString(g)} }

func TestTrustPinsTheFirstRoot(t *testing.T) {
	dir := t.TempDir()
	r1, r2 := root("ws", "g1"), root("ws", "g2")
	tr := OpenTrust(dir, clock.New())
	if err := tr.Check(r1, "/repo/enbu.toml", PinFirst); err != nil {
		t.Fatalf("nothing pinned yet: %v", err)
	}
	if prev, err := tr.Pin(r1, "/repo/enbu.toml", PinFirst); err != nil || prev != (Root{}) {
		t.Fatalf("first pin: %v %v", prev, err)
	}
	if prev, err := tr.Pin(r1, "/repo/enbu.toml", PinFirst); err != nil || prev != (Root{}) {
		t.Fatalf("pinning the same root again: %v %v", prev, err)
	}
	// A fresh handle reads the pin back from disk.
	tr = OpenTrust(dir, clock.New())
	var changed *TrustRootChangedError
	if err := tr.Check(r2, "/other/enbu.toml", PinFirst); !errors.As(err, &changed) || changed.Pinned != r1 || changed.Configured != r2 {
		t.Fatalf("Check accepted another genesis: %v", err)
	}
	if _, err := tr.Pin(r2, "", PinFounded); !errors.As(err, &changed) {
		t.Fatalf("founding replaced the workspace pin: %v", err)
	}
	if _, err := tr.Pin(r2, "", PinFirst); !errors.As(err, &changed) {
		t.Fatalf("Pin replaced the root without replace: %v", err)
	}
	if got, _ := tr.Pinned("ws"); got != r1 {
		t.Fatalf("pin changed to %v", got)
	}
	if prev, err := tr.Pin(r2, "/repo/enbu.toml", PinReplace); err != nil || prev != r1 {
		t.Fatalf("replace: %v %v", prev, err)
	}
	if err := tr.Check(r2, "/repo/enbu.toml", PinFirst); err != nil {
		t.Fatalf("replaced root rejected: %v", err)
	}
	if got, _ := tr.Repository("/repo/enbu.toml"); got != r2 {
		t.Fatalf("repository pin is %v", got)
	}
}

// The repository pin compares the workspace too, so changing both fields of
// enbu.toml is still a change of trust root.
func TestTrustRepositoryComparesTheWorkspace(t *testing.T) {
	tr := OpenTrust(t.TempDir(), clock.New())
	ws1, ws2 := root("ws1", "g1"), root("ws2", "g2")
	if _, err := tr.Pin(ws1, "/repo/enbu.toml", PinFirst); err != nil {
		t.Fatal(err)
	}
	var changed *TrustRootChangedError
	if err := tr.Check(ws2, "/repo/enbu.toml", PinFirst); !errors.As(err, &changed) || changed.Pinned != ws1 {
		t.Fatalf("another workspace was accepted: %v", err)
	}
	if _, err := tr.Pin(ws2, "/repo/enbu.toml", PinFirst); !errors.As(err, &changed) {
		t.Fatalf("another workspace was pinned: %v", err)
	}
	if err := tr.Check(ws2, "/other/enbu.toml", PinFirst); err != nil {
		t.Fatalf("a pin leaked to another repository: %v", err)
	}
	if err := tr.Check(ws2, "", PinFirst); err != nil {
		t.Fatalf("an unknown repository was compared: %v", err)
	}
	// Founding a new workspace moves the repository and reports nothing replaced.
	if prev, err := tr.Pin(ws2, "/repo/enbu.toml", PinFounded); err != nil || prev != ws1 {
		t.Fatalf("founding did not move the repository: %v %v", prev, err)
	}
	if got, _ := tr.Repository("/repo/enbu.toml"); got != ws2 {
		t.Fatalf("repository pin is %v", got)
	}
	if got, _ := tr.Pinned("ws1"); got != ws1 {
		t.Fatalf("moving the repository dropped the workspace pin: %v", got)
	}
}

func TestTrustRejectsACorruptFileUnlessReplaced(t *testing.T) {
	dir := t.TempDir()
	tr := OpenTrust(dir, clock.New())
	if err := os.WriteFile(filepath.Join(dir, "trust.json"), []byte(`{"workspaces":{"ws":"nope"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tr.Check(root("ws", "g"), "", PinFirst); err == nil {
		t.Fatal("a corrupt pin was accepted")
	}
	if _, err := tr.Pin(root("ws", "g"), "", PinFounded); err == nil {
		t.Fatal("a corrupt pin was overwritten without replace")
	}
	if _, err := tr.Pin(root("ws", "g"), "", PinReplace); err != nil {
		t.Fatalf("replace could not repair a corrupt pin: %v", err)
	}
	if got, err := tr.Pinned("ws"); err != nil || got != root("ws", "g") {
		t.Fatalf("repaired pin: %v %v", got, err)
	}
}

// Confirming one workspace's new root repairs its own pin only. A file that
// also holds another corrupt pin, or is not a trust file at all, is not reset.
func TestTrustReplaceKeepsOtherPins(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	tr := OpenTrust(dir, clock.New())
	other := root("other", "o")
	file := `{"workspaces":{"ws":"nope","other":"` + string(other.Genesis) + `"},"repositories":{"/b/enbu.toml":"other"}}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Pin(root("ws", "g"), "/a/enbu.toml", PinReplace); err != nil {
		t.Fatalf("replace could not repair its own pin: %v", err)
	}
	if got, err := tr.Pinned("other"); err != nil || got != other {
		t.Fatalf("another workspace's pin: %v %v", got, err)
	}
	if got, err := tr.Repository("/b/enbu.toml"); err != nil || got != other {
		t.Fatalf("another checkout's pin: %v %v", got, err)
	}

	// A file that is not a trust file at all is not reset.
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Pin(root("ws", "g"), "", PinReplace); err == nil {
		t.Fatal("replace reset a file that is not a trust file")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != `{` {
		t.Fatalf("the file changed: %s %v", b, err)
	}
}

// A damaged pin of one workspace or checkout stops only that workspace or
// checkout, and survives the other pins being written.
func TestTrustCorruptPinStopsOnlyItsOwnWorkspace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.json")
	tr := OpenTrust(dir, clock.New())
	file := `{"workspaces":{"broken":"nope"},"repositories":{"/b/enbu.toml":"broken","/c/enbu.toml":""}}`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := root("ws", "g")
	if err := tr.Check(ws, "/a/enbu.toml", PinFirst); err != nil {
		t.Fatalf("another workspace's damaged pin stopped this one: %v", err)
	}
	if _, err := tr.Pin(ws, "/a/enbu.toml", PinFirst); err != nil {
		t.Fatalf("pin beside a damaged pin: %v", err)
	}
	if got, err := tr.Pinned("ws"); err != nil || got != ws {
		t.Fatalf("pinned = %v %v", got, err)
	}
	if got, err := tr.Repository("/a/enbu.toml"); err != nil || got != ws {
		t.Fatalf("repository = %v %v", got, err)
	}
	for name, read := range map[string]func() error{
		"workspace":           func() error { _, err := tr.Pinned("broken"); return err },
		"its checkout":        func() error { _, err := tr.Repository("/b/enbu.toml"); return err },
		"an empty checkout":   func() error { _, err := tr.Repository("/c/enbu.toml"); return err },
		"check of the root":   func() error { return tr.Check(root("broken", "g"), "", PinFirst) },
		"check of a checkout": func() error { return tr.Check(ws, "/c/enbu.toml", PinFirst) },
	} {
		if err := read(); err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("%s: damaged pin read as %v", name, err)
		}
	}
	// Writing this workspace's pin kept the damaged ones for a person to repair.
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), `"broken": "nope"`) || !strings.Contains(string(b), `"/c/enbu.toml": ""`) {
		t.Fatalf("damaged pins were dropped: %s %v", b, err)
	}
}

func TestTrustRejectsAnInvalidRoot(t *testing.T) {
	tr := OpenTrust(t.TempDir(), clock.New())
	if _, err := tr.Pin(Root{Workspace: "ws", Genesis: "sha256:short"}, "", PinFirst); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pinned an invalid digest: %v", err)
	}
	if _, err := tr.Pin(Root{Genesis: digest.FromString("g")}, "", PinFirst); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pinned a root without a workspace: %v", err)
	}
}

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

func writeOutput(t *testing.T, a *App, content string) string {
	t.Helper()
	path := filepath.Join(a.RepositoryDir, ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A variable the file holds but enbu does not store is kept, below a marker,
// and reported, so a pull never silently throws away a local setting.
func TestPullKeepsVariablesEnbuDoesNotStore(t *testing.T) {
	alice := newAlice(t) // KEY=v1
	path := writeOutput(t, alice, "KEY=\"old\"\nLOCAL_ONLY=\"1\"\n")
	kept, err := alice.PullSecretsToFileWith(bg, "default", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0] != "LOCAL_ONLY" {
		t.Fatalf("kept = %v", kept)
	}
	got, _ := os.ReadFile(path)
	text := string(got)
	if !strings.Contains(text, "KEY=\"v1\"") || !strings.Contains(text, "LOCAL_ONLY=\"1\"") || strings.Contains(text, "\"old\"") {
		t.Fatalf("file:\n%s", text)
	}
	if !strings.Contains(text, "# Kept from the previous file") {
		t.Fatalf("no marker:\n%s", text)
	}
	// Pulling again keeps it again, once, without piling up markers.
	if _, err := alice.PullSecretsToFileWith(bg, "default", false); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if strings.Count(string(got), "LOCAL_ONLY=") != 1 || strings.Count(string(got), "# Kept") != 1 {
		t.Fatalf("second pull:\n%s", got)
	}
}

func TestPullReplaceDropsLocalVariables(t *testing.T) {
	alice := newAlice(t)
	path := writeOutput(t, alice, "LOCAL_ONLY=\"1\"\n")
	kept, err := alice.PullSecretsToFileWith(bg, "default", true)
	if err != nil || len(kept) != 0 {
		t.Fatalf("kept = %v, err = %v", kept, err)
	}
	if got, _ := os.ReadFile(path); strings.Contains(string(got), "LOCAL_ONLY") {
		t.Fatalf("replace kept a variable:\n%s", got)
	}
}

func TestPullRefusesToOverwriteWhatItCannotRead(t *testing.T) {
	alice := newAlice(t)
	writeOutput(t, alice, "this is not dotenv\n")
	if _, err := alice.PullSecretsToFileWith(bg, "default", false); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Fatalf("unreadable file overwritten: %v", err)
	}
	if _, err := alice.PullSecretsToFileWith(bg, "default", true); err != nil {
		t.Fatalf("replace: %v", err)
	}
}

func TestPullWritesAFreshFileWithoutAMarker(t *testing.T) {
	alice := newAlice(t)
	if _, err := alice.PullSecretsToFileWith(bg, "default", false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(alice.RepositoryDir, ".env"))
	if string(got) != "KEY=\"v1\"\n" {
		t.Fatalf("file:\n%s", got)
	}
}

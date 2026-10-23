package app

import (
	"errors"
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
	written, err := alice.PullSecretsToFileWith(bg, "default", false)
	if err != nil {
		t.Fatal(err)
	}
	if kept := written.Kept; len(kept) != 1 || kept[0] != "LOCAL_ONLY" || written.Count != 1 || written.Output != ".env" {
		t.Fatalf("written = %+v", written)
	}
	got, _ := os.ReadFile(path)
	text := string(got)
	if !strings.Contains(text, "KEY=\"v1\"") || !strings.Contains(text, "LOCAL_ONLY=\"1\"") || strings.Contains(text, "\"old\"") {
		t.Fatalf("file:\n%s", text)
	}
	if !strings.Contains(text, keptMarker+"\nLOCAL_ONLY") {
		t.Fatalf("no marker:\n%s", text)
	}
	// Pulling again keeps it again, once, without piling up markers.
	if _, err := alice.PullSecretsToFileWith(bg, "default", false); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if strings.Count(string(got), "LOCAL_ONLY=") != 1 || strings.Count(string(got), keptMarker) != 1 {
		t.Fatalf("second pull:\n%s", got)
	}
}

func TestPullReplaceDropsLocalVariables(t *testing.T) {
	alice := newAlice(t)
	path := writeOutput(t, alice, "LOCAL_ONLY=\"1\"\n")
	written, err := alice.PullSecretsToFileWith(bg, "default", true)
	if err != nil || len(written.Kept) != 0 {
		t.Fatalf("written = %+v, err = %v", written, err)
	}
	if got, _ := os.ReadFile(path); strings.Contains(string(got), "LOCAL_ONLY") {
		t.Fatalf("replace kept a variable:\n%s", got)
	}
}

func TestPullRefusesToOverwriteWhatItCannotRead(t *testing.T) {
	alice := newAlice(t)
	writeOutput(t, alice, "this is not dotenv\n")
	_, err := alice.PullSecretsToFileWith(bg, "default", false)
	var appErr *apperr.Error
	if !apperr.Is(err, apperr.CodeOutputUnreadable) || !errors.As(err, &appErr) || appErr.Params()["file"] != ".env" {
		t.Fatalf("unreadable file overwritten: %v", err)
	}
	if _, err := alice.PullSecretsToFileWith(bg, "default", true); err != nil {
		t.Fatalf("replace: %v", err)
	}
}

// A fresh file holds the secrets and the marker, below which local variables go.
func TestPullWritesAFreshFileWithTheMarker(t *testing.T) {
	alice := newAlice(t)
	if _, err := alice.PullSecretsToFileWith(bg, "default", false); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(alice.RepositoryDir, ".env"))
	if string(got) != "KEY=\"v1\"\n\n"+keptMarker+"\n" {
		t.Fatalf("file:\n%s", got)
	}
}

// A secret deleted from the environment leaves the file on the next pull and
// is reported, instead of staying on disk in plaintext as a "local" variable.
// Variables below the marker stay.
func TestPullRemovesSecretsTheEnvironmentNoLongerHas(t *testing.T) {
	alice := newAlice(t)
	if err := alice.AddSecret(bg, "default", "TOKEN", "revoked"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.PullSecretsToFileWith(bg, "default", false); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(alice.RepositoryDir, ".env")
	got, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(got, "LOCAL_ONLY=\"1\"\n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := alice.DeleteSecret(bg, "default", "TOKEN"); err != nil {
		t.Fatal(err)
	}
	written, err := alice.PullSecretsToFileWith(bg, "default", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(written.Removed) != 1 || written.Removed[0] != "TOKEN" || len(written.Kept) != 1 || written.Kept[0] != "LOCAL_ONLY" {
		t.Fatalf("written = %+v", written)
	}
	got, _ = os.ReadFile(path)
	if text := string(got); strings.Contains(text, "revoked") || !strings.Contains(text, keptMarker+"\nLOCAL_ONLY=\"1\"\n") {
		t.Fatalf("file:\n%s", text)
	}
	messages := strings.Join(written.Messages(), "\n")
	if !strings.Contains(messages, "Removed 1 variable(s) no longer in the environment: TOKEN") || !strings.Contains(messages, "Kept 1 local variable(s)") {
		t.Fatalf("messages = %q", messages)
	}
}

// A file from before enbu wrote a marker has no way to say which variables an
// earlier pull wrote. A variable the environment once stored and no longer does
// is enbu's own, deleted since, and leaves the file; the rest are kept.
func TestPullWithoutMarkerRemovesSecretsTheEnvironmentOnceHeld(t *testing.T) {
	alice := newAlice(t)
	if err := alice.AddSecret(bg, "default", "TOKEN", "revoked"); err != nil {
		t.Fatal(err)
	}
	if err := alice.DeleteSecret(bg, "default", "TOKEN"); err != nil {
		t.Fatal(err)
	}
	path := writeOutput(t, alice, "KEY=\"v1\"\nTOKEN=\"revoked\"\nLOCAL_ONLY=\"1\"\n")
	written, err := alice.PullSecretsToFileWith(bg, "default", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(written.Removed) != 1 || written.Removed[0] != "TOKEN" || len(written.Kept) != 1 || written.Kept[0] != "LOCAL_ONLY" {
		t.Fatalf("written = %+v", written)
	}
	got, _ := os.ReadFile(path)
	if text := string(got); strings.Contains(text, "revoked") || !strings.Contains(text, keptMarker+"\nLOCAL_ONLY=\"1\"\n") {
		t.Fatalf("file:\n%s", text)
	}
}

// Only a file with variables enbu does not hold now needs the history.
func TestPullWithoutMarkerReadsHistoryOnlyWhenNeeded(t *testing.T) {
	alice := newAlice(t)
	writeOutput(t, alice, "KEY=\"old\"\n")
	calls := 0
	stored := func() (map[string]bool, error) { calls++; return nil, nil }
	if _, _, _, err := dotenvWithLocal(filepath.Join(alice.RepositoryDir, ".env"), map[string]string{"KEY": "v1"}, false, stored); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("history read %d times for a file enbu fully owns", calls)
	}
}

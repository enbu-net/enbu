package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
)

// The desktop reports what a pull kept and removed, and can overwrite a file
// enbu cannot read, which the CLI does with --replace.
func TestDesktopPullReportsAndCanReplace(t *testing.T) {
	f := newMembersFixture(t)
	if err := f.alice.AddSecret("", "KEY", "v1"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.alice.repoPath, ".env")
	if err := os.WriteFile(path, []byte("LOCAL_ONLY=\"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := f.alice.PullSecrets("", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Output != ".env" || result.Count != 1 || len(result.Kept) != 1 || result.Kept[0] != "LOCAL_ONLY" || result.Removed == nil {
		t.Fatalf("result = %+v", result)
	}

	if err := os.WriteFile(path, []byte("not dotenv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.alice.PullSecrets("", false); !apperr.Is(err, apperr.CodeOutputUnreadable) {
		t.Fatalf("unreadable file: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "not dotenv\n" {
		t.Fatalf("the file was overwritten without replace:\n%s", got)
	}
	result, err = f.alice.PullSecrets("", true)
	if err != nil || len(result.Kept) != 0 {
		t.Fatalf("replace: %+v %v", result, err)
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "KEY=\"v1\"") {
		t.Fatalf("file after replace:\n%s", got)
	}
}

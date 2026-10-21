package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Without a VALUE argument the value comes from stdin, so it never lands in
// shell history or process listings.
func TestAddAndEditReadTheValueFromStdin(t *testing.T) {
	a, _ := newSeededApp(t, nil)
	cmd := NewWithApp("test", a)
	cmd.SetIn(bytes.NewBufferString("line1\nline2\n"))
	executeJSON(t, cmd, "add", "CERT", "--json")
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil || got["CERT"] != "line1\nline2" {
		t.Fatalf("stdin value: %q %v", got["CERT"], err)
	}
	cmd = NewWithApp("test", a)
	cmd.SetIn(bytes.NewBufferString("changed"))
	executeJSON(t, cmd, "edit", "CERT", "--json")
	if got, _ := a.ListSecrets(context.Background(), "default"); got["CERT"] != "changed" {
		t.Fatalf("edit from stdin: %q", got["CERT"])
	}
}

func TestAddReadsTheValueFromAFile(t *testing.T) {
	a, _ := newSeededApp(t, nil)
	path := filepath.Join(t.TempDir(), "value.txt")
	if err := os.WriteFile(path, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executeJSON(t, NewWithApp("test", a), "add", "FROM_FILE", "--value-file", path, "--json")
	if got, _ := a.ListSecrets(context.Background(), "default"); got["FROM_FILE"] != "from-file" {
		t.Fatalf("file value: %q", got["FROM_FILE"])
	}
	cmd := NewWithApp("test", a)
	if _, err := executeJSONResult(t, cmd, "add", "BOTH", "v", "--value-file", path, "--json"); err == nil {
		t.Fatal("a value argument and --value-file together were accepted")
	}
}

func TestAddWithAnEmptyStdinFails(t *testing.T) {
	a, _ := newSeededApp(t, nil)
	cmd := NewWithApp("test", a)
	cmd.SetIn(bytes.NewBufferString(""))
	if _, err := executeJSONResult(t, cmd, "add", "EMPTY", "--json"); err == nil {
		t.Fatal("an empty value was accepted silently")
	}
}

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestImportReadsADotenvFile(t *testing.T) {
	a, _ := newSeededApp(t, map[string]string{"KEY": "value"})
	path := filepath.Join(t.TempDir(), "app.env")
	if err := os.WriteFile(path, []byte("# comment\nexport NEW=\"multi\\nline\"\nKEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := executeJSON(t, NewWithApp("test", a), "import", path, "--json")
	data := objectField(t, res, "data")
	if added, _ := data["added"].([]any); len(added) != 1 || added[0] != "NEW" {
		t.Fatalf("added = %v", data["added"])
	}
	got, err := a.ListSecrets(context.Background(), "default")
	if err != nil || got["NEW"] != "multi\nline" || got["KEY"] != "value" {
		t.Fatalf("secrets = %v %v", got, err)
	}
}

func TestImportReadsStdinAndRefusesToChangeWithoutOverwrite(t *testing.T) {
	a, _ := newSeededApp(t, map[string]string{"KEY": "value"})
	cmd := NewWithApp("test", a)
	cmd.SetIn(bytes.NewBufferString("KEY=other\n"))
	if _, err := executeJSONResult(t, cmd, "import", "-", "--json"); err == nil {
		t.Fatal("existing key changed without --overwrite")
	}
	cmd = NewWithApp("test", a)
	cmd.SetIn(bytes.NewBufferString("KEY=other\n"))
	res := executeJSON(t, cmd, "import", "-", "--overwrite", "--json")
	if updated, _ := objectField(t, res, "data")["updated"].([]any); len(updated) != 1 {
		t.Fatalf("updated = %v", objectField(t, res, "data")["updated"])
	}
}

func TestImportRejectsMalformedDotenv(t *testing.T) {
	a, _ := newSeededApp(t, nil)
	cmd := NewWithApp("test", a)
	cmd.SetIn(bytes.NewBufferString("not an assignment\n"))
	if _, err := executeJSONResult(t, cmd, "import", "-", "--json"); err == nil {
		t.Fatal("malformed input accepted")
	}
}

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPullWarnsAboutKeptLocalVariables(t *testing.T) {
	a, _ := newSeededApp(t, map[string]string{"KEY": "value"})
	path := filepath.Join(a.RepositoryDir, ".env")
	if err := os.WriteFile(path, []byte("LOCAL_ONLY=\"1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewWithApp("test", a)
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"pull"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut.String(), "✓ Written .env (1 secrets)") || !strings.Contains(errOut.String(), "LOCAL_ONLY") || !strings.Contains(errOut.String(), "--replace") {
		t.Fatalf("stderr: %q", errOut.String())
	}
	cmd = NewWithApp("test", a)
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"pull", "--replace"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); strings.Contains(string(got), "LOCAL_ONLY") {
		t.Fatalf("--replace kept the variable:\n%s", got)
	}
}

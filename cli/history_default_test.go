package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHistoryWithoutASubcommandLists(t *testing.T) {
	a, _ := newSeededApp(t, nil)
	if err := a.AddSecret(context.Background(), "default", "A", "1"); err != nil {
		t.Fatal(err)
	}
	list := executeJSON(t, NewWithApp("test", a), "history", "--json")
	if entries, _ := objectField(t, list, "data")["entries"].([]any); len(entries) != 1 {
		t.Fatalf("entries = %#v", objectField(t, list, "data")["entries"])
	}
	cmd := NewWithApp("test", a)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"history"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "(latest)") || strings.Contains(out.String(), "hist-") {
		t.Fatalf("human listing should number entries and hide storage tags:\n%s", out.String())
	}
}

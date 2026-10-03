//go:build enbucoverage

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/tobari"
	"github.com/spf13/cobra"
)

func TestCoverageRecordsSuccessAndFailureWithoutSecretArguments(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ENBU_TEST_COVERAGE_DIR", dir)
	t.Setenv("ENBU_TEST_COVERAGE_NAME", "fixture")
	originalArgs := os.Args
	os.Args = []string{"enbu", "add", "API_KEY", "secret-value"}
	t.Cleanup(func() { os.Args = originalArgs })
	failure := errors.New("expected failure")
	for _, want := range []error{nil, failure} {
		root := &cobra.Command{Use: "enbu", SilenceErrors: true, SilenceUsage: true}
		root.AddCommand(&cobra.Command{
			Use: "add", RunE: func(_ *cobra.Command, _ []string) error { return want },
		})
		root.SetArgs(os.Args[1:])
		if err := executeCommand(context.Background(), root); !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) != 2 {
		t.Fatalf("reports = %v, error = %v", files, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var report tobari.CoverReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, count := range report.Counts {
			found = found || count.Name == "fixture/enbu add"
			if strings.Contains(count.Name, "secret-value") || strings.Contains(count.Name, "API_KEY") {
				t.Fatalf("secret argument in scope name: %s", count.Name)
			}
		}
		if !found {
			t.Fatal("missing CLI scope")
		}
		if _, err := os.Stat(file + ".toon"); err != nil {
			t.Fatal(err)
		}
	}
}

//go:build enbucoverage

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/tobari"
	"github.com/spf13/cobra"
)

func executeCommand(ctx context.Context, command *cobra.Command) error {
	dir := os.Getenv("ENBU_TEST_COVERAGE_DIR")
	if dir == "" {
		return runCommand(ctx, command)
	}

	// Command paths contain registered command names, never secret arguments.
	name := os.Getenv("ENBU_TEST_COVERAGE_NAME")
	if name == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		name = "E2E/" + filepath.Base(cwd)
	}
	if cmd, _, err := command.Find(os.Args[1:]); err == nil {
		name += "/" + cmd.CommandPath()
	}
	var runErr error
	tobari.CoverWithName(name, func() {
		runErr = runCommand(ctx, command)
	})
	return errors.Join(runErr, writeCoverageReport(dir))
}

func writeCoverageReport(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create coverage directory: %w", err)
	}
	file, err := os.CreateTemp(dir, "cli-*.json")
	if err != nil {
		return fmt.Errorf("create coverage report: %w", err)
	}
	report := tobari.CollectCoverReport()
	writeErr := json.NewEncoder(file).Encode(report)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return fmt.Errorf("write coverage report: %w", err)
	}
	toon, err := report.MarshalTOON()
	if err != nil {
		return err
	}
	return os.WriteFile(file.Name()+".toon", toon, 0o600)
}

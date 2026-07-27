package cli

import (
	"fmt"
	"io"

	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func newExportCommand(a *app.App) *cobra.Command {
	var envName string
	var toStdout bool

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export cached secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDotenvExport(cmd, a, envName, toStdout)
		},
	}
	cmd.PersistentFlags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	cmd.Flags().BoolVar(&toStdout, "stdout", false, "Output dotenv to stdout instead of the configured file")

	var dotenvStdout bool
	dotenvCmd := &cobra.Command{
		Use:   "dotenv",
		Short: "Export cached secrets in dotenv format",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDotenvExport(cmd, a, envName, dotenvStdout)
		},
	}
	dotenvCmd.Flags().BoolVar(&dotenvStdout, "stdout", false, "Output dotenv to stdout instead of the configured file")
	cmd.AddCommand(dotenvCmd)

	return cmd
}

func runDotenvExport(cmd *cobra.Command, a *app.App, envName string, toStdout bool) error {
	var writer io.Writer
	if toStdout {
		writer = cmd.OutOrStdout()
	}
	result, err := a.ExportSecrets(cmd.Context(), envName, app.DotenvExporter{
		RepositoryDir: a.RepositoryDir,
		Writer:        writer,
	})
	if err != nil {
		return err
	}
	if !toStdout {
		_, err = fmt.Fprintf(cmd.ErrOrStderr(), "✓ Exported %s (%d secrets)\n", result.Destination, result.Count)
	}
	return err
}

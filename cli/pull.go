package cli

import (
	"fmt"
	"os"

	"github.com/enbu-net/enbu/internal/application"
	"github.com/spf13/cobra"
)

func newPullCommand(a *app.App) *cobra.Command {
	var toStdout bool
	var envName string

	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull and decrypt secrets into .env",
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonEnabled(cmd) {
				if toStdout {
					return invalidArgument("--stdout cannot be used with --json", nil)
				}
				result, err := a.PullSecretsData(cmd.Context(), envName)
				if err != nil {
					return err
				}
				return writeJSON(cmd, map[string]any{
					"environment": result.Environment,
					"count":       len(result.Secrets),
					"secrets":     result.Secrets,
				})
			}

			dotenv, output, count, err := a.PullSecrets(cmd.Context(), envName)
			if err != nil {
				return err
			}

			if toStdout {
				_, _ = cmd.OutOrStdout().Write(dotenv)
				return nil
			}

			if err := os.WriteFile(output, dotenv, 0o600); err != nil {
				return fmt.Errorf("writing %s: %w", output, err)
			}

			cmd.PrintErrf("✓ Written %s (%d secrets)\n", output, count)
			return nil
		},
	}

	cmd.Flags().BoolVar(&toStdout, "stdout", false, "Output to stdout instead of .env file")
	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	return cmd
}

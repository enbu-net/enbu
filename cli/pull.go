package cli

import (
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func newPullCommand(a *app.App) *cobra.Command {
	var toStdout bool
	var replace bool
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

			if toStdout {
				dotenv, _, _, err := a.PullSecrets(cmd.Context(), envName)
				if err != nil {
					return err
				}
				_, _ = cmd.OutOrStdout().Write(dotenv)
				return nil
			}

			written, err := a.PullSecretsToFileWith(cmd.Context(), envName, replace)
			if err != nil {
				return err
			}
			cmd.PrintErrf("✓ Written %s (%d secrets)\n", written.Output, written.Count)
			if len(written.Kept) > 0 {
				cmd.PrintErrf("Kept %d local variable(s) enbu does not store: %s (pull --replace drops them)\n", len(written.Kept), strings.Join(written.Kept, ", "))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&toStdout, "stdout", false, "Output to stdout instead of .env file")
	cmd.Flags().BoolVar(&replace, "replace", false, "Overwrite the output file even if it holds variables enbu does not store")
	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	return cmd
}

package cli

import (
	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func newAddCommand(a *app.App) *cobra.Command {
	var envName string
	var valueFile string

	cmd := &cobra.Command{
		Use:   "add KEY [VALUE]",
		Short: "Add a secret to the repository",
		Long:  "Without VALUE the value is read from stdin (a hidden prompt on a terminal) or from --value-file, so it stays out of shell history.",
		Args:  appArgs(cobra.RangeArgs(1, 2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			value, err := secretValue(cmd, args, valueFile)
			if err != nil {
				return err
			}
			if err := a.AddSecret(cmd.Context(), envName, args[0], value); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"action":      "add",
					"environment": resolvedEnvironmentName(a, envName),
					"key":         args[0],
				})
			}
			cmd.Printf("✓ Added %s\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	cmd.Flags().StringVar(&valueFile, "value-file", "", "Read the value from this file (\"-\" for stdin)")
	return cmd
}

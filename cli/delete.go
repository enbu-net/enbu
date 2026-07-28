package cli

import (
	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func newDeleteCommand(a *app.App) *cobra.Command {
	var envName string

	cmd := &cobra.Command{
		Use:   "delete KEY",
		Short: "Delete a secret from the repository",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.DeleteSecret(cmd.Context(), envName, args[0]); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"action":      "delete",
					"environment": resolvedEnvironmentName(a, envName),
					"key":         args[0],
				})
			}
			cmd.Printf("✓ Deleted %s\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	return cmd
}

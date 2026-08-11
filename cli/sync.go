package cli

import (
	"github.com/enbu-net/enbu/internal/application"
	"github.com/spf13/cobra"
)

func newSyncCommand(a *app.App) *cobra.Command {
	var envName string

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Re-encrypt secrets for all current recipients",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.SyncSecrets(cmd.Context(), envName); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"action":      "sync",
					"environment": resolvedEnvironmentName(a, envName),
				})
			}
			cmd.Println("✓ Sync complete")
			return nil
		},
	}

	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	return cmd
}

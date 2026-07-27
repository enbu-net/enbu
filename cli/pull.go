package cli

import (
	"fmt"

	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func newPullCommand(a *app.App) *cobra.Command {
	var envName string

	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull encrypted secrets into the local cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			count, found, err := a.PullSecrets(cmd.Context(), envName)
			if err != nil {
				return err
			}
			if !found {
				_, err = fmt.Fprintln(cmd.ErrOrStderr(), "No secrets have been uploaded for this environment.")
				return err
			}
			_, err = fmt.Fprintf(cmd.ErrOrStderr(), "✓ Pulled %d secrets into the local cache\n", count)
			return err
		},
	}

	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	return cmd
}

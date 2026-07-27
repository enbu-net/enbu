package cli

import (
	"github.com/enbu-net/enbu/app"
	gitprovider "github.com/enbu-net/enbu/provider/git"
	"github.com/enbu-net/enbu/tui"
	"github.com/spf13/cobra"
)

func New(version string) *cobra.Command {
	return NewWithApp(version, app.New())
}

func NewWithApp(version string, a *app.App) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "enbu",
		Short:        "Keyless .env management powered by GitHub",
		Version:      version,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return tui.Run(a)
		},
	}

	rootCmd.AddCommand(
		newAuthCommand(a),
		newInitCommand(a),
		newSwitchCommand(a),
		newAddCommand(a),
		newEditCommand(a),
		newDeleteCommand(a),
		newPullCommand(a),
		newExportCommand(a),
		newSyncCommand(a),
		newHistoryCommand(a),
	)

	return rootCmd
}

func gitClient(a *app.App) gitprovider.Client {
	if a.Git != nil {
		return a.Git
	}
	return gitprovider.NewCLIClient()
}

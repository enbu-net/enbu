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
	var (
		jsonOutput  bool
		showVersion bool
	)

	rootCmd := &cobra.Command{
		Use:           "enbu",
		Short:         "Keyless .env management powered by GitHub",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				if jsonEnabled(cmd) {
					return writeJSON(cmd, map[string]string{"version": version})
				}
				cmd.Printf("%s version %s\n", cmd.Name(), version)
				return nil
			}
			if jsonEnabled(cmd) {
				return renderHelp(cmd)
			}
			return tui.Run(a)
		},
	}
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output one JSON response")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "version for enbu")
	defaultHelp := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		if jsonEnabled(cmd) {
			_ = writeJSON(cmd, commandHelp(cmd))
			return
		}
		defaultHelp(cmd, nil)
	})

	rootCmd.AddCommand(
		newAuthCommand(a),
		newInitCommand(a),
		newSwitchCommand(a),
		newAddCommand(a),
		newEditCommand(a),
		newDeleteCommand(a),
		newPullCommand(a),
		newSyncCommand(a),
		newHistoryCommand(a),
		newCompletionCommand(rootCmd),
	)

	return rootCmd
}

func gitClient(a *app.App) gitprovider.Client {
	if a.Git != nil {
		return a.Git
	}
	return gitprovider.NewCLIClient()
}

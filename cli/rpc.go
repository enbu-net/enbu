package cli

import (
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/desktop/rpc"
	"github.com/spf13/cobra"
)

// newRPCCommand serves the desktop app's backend to an editor extension over
// stdin and stdout. It is hidden: people use the CLI or the extension, not this.
func newRPCCommand(version string, a *app.App) *cobra.Command {
	var stdio bool

	cmd := &cobra.Command{
		Use:    "rpc",
		Short:  "Serve the desktop backend over JSON-RPC for editor extensions",
		Hidden: true,
		Args:   appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !stdio {
				return invalidArgument("rpc needs --stdio", nil)
			}
			core := desktop.NewService(a)
			core.AppVersion = version
			return rpc.NewServer(core).Serve(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}

	cmd.Flags().BoolVar(&stdio, "stdio", false, "Talk JSON-RPC over stdin and stdout")
	return cmd
}

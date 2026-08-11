//go:build legacy

package cli

import (
	"github.com/enbu-net/enbu/pkg/client"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/spf13/cobra"
)

// HostCommandOptions supplies trusted host actions to the CLI. The command
// accepts only an action name; resource handles and payloads stay in Go.
type HostCommandOptions struct {
	Controller *client.Controller
	Actions    map[string]host.Action
}

// NewHostCommand builds the host-backed operation command used by the
// platform-native CLI entry point. It is separate from the legacy command
// tree so production callers can switch once without a compatibility shim.
func NewHostCommand(options HostCommandOptions) *cobra.Command {
	command := &cobra.Command{Use: "host", Short: "Run a host operation"}
	run := &cobra.Command{
		Use:   "run ACTION",
		Short: "Run a trusted host operation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			action, ok := options.Actions[args[0]]
			if !ok {
				return invalidArgument("unknown host operation", nil)
			}
			return options.Controller.RunCLI(cmd.Context(), args[0], action, cmd.OutOrStdout())
		},
	}
	command.AddCommand(run)
	return command
}

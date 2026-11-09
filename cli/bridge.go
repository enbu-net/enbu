package cli

import (
	"errors"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/keystore"
	"github.com/enbu-net/enbu/pkg/winbridge"
	"github.com/spf13/cobra"
)

// inWSL is winbridge.InWSL, replaced in tests so they behave the same on a
// WSL host.
var inWSL = winbridge.InWSL

// newIdentityBridgeCommand serves this device's key operations to the enbu
// inside WSL, which starts it as enbu.exe. It is hidden: nobody runs it by
// hand.
func newIdentityBridgeCommand(version string, a *app.App) *cobra.Command {
	var stdio bool
	cmd := &cobra.Command{
		Use:    "bridge",
		Short:  "Serve key operations to enbu inside WSL",
		Hidden: true,
		Args:   appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !stdio {
				return invalidArgument("bridge needs --stdio", nil)
			}
			if inWSL() {
				return invalidArgument("the identity bridge runs in Windows, not inside WSL", nil)
			}
			store, ok := a.Identities.(winbridge.Store)
			if !ok {
				return errors.New("this identity store cannot serve the bridge")
			}
			service, key := auth.TokenKeyringEntry()
			s := &winbridge.Server{Version: version, Identities: store, Keyring: keystore.New(),
				Entries: []winbridge.KeyringEntry{{Service: service, Key: key}}}
			return s.Serve(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&stdio, "stdio", false, "Talk over stdin and stdout")
	return cmd
}

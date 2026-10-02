package cli

import (
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/spf13/cobra"
)

func printIdentity(cmd *cobra.Command, info identity.PublicInfo, warning string) error {
	if jsonEnabled(cmd) {
		if warning != "" {
			return writeJSON(cmd, info, warning)
		}
		return writeJSON(cmd, info)
	}
	cmd.Printf("Backend: %s\nAlgorithm: %s\nRecipient: %s\n", info.Backend, info.Algorithm, info.Recipient)
	if info.Device != "" {
		cmd.Printf("Device: %s\n", info.Device)
	}
	if warning != "" {
		cmd.PrintErrln(warning)
	}
	return nil
}

func newIdentityCommand(a *app.App) *cobra.Command {
	cmd := &cobra.Command{Use: "identity", Short: "Manage this repository's local Identity"}
	cmd.AddCommand(&cobra.Command{Use: "create", Short: "Create or reuse a local Identity without registration", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, warning, err := a.CreateIdentity()
			if err != nil {
				return err
			}
			return printIdentity(cmd, info, warning)
		}})
	cmd.AddCommand(&cobra.Command{Use: "show", Short: "Show validated Identity public information", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := a.IdentityInfo()
			if err != nil {
				return err
			}
			return printIdentity(cmd, info, "")
		}})
	return cmd
}

func newDoctorCommand(a *app.App) *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Probe hardware and OS keyring without authentication or persistent keys", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := a.DiagnoseIdentity()
			if jsonEnabled(cmd) {
				return writeJSON(cmd, d)
			}
			cmd.Printf("Hardware: %s\nDevice: %s\nAvailable: %t\n", d.Backend, d.Device, d.Available)
			if d.Reason != "" {
				cmd.Printf("Reason: %s\n", d.Reason)
			}
			cmd.Printf("OS keyring fallback available: %t\n", d.FallbackAvailable)
			if d.FallbackReason != "" {
				cmd.Printf("Keyring: %s\n", d.FallbackReason)
			}
			return nil
		}}
}

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
	cmd.AddCommand(&cobra.Command{Use: "upgrade", Short: "Switch this device to a post-quantum (hybrid ML-KEM) encryption key", Args: appArgs(cobra.NoArgs),
		Long: "Create a hybrid ML-KEM-768 encryption key and ask an admin to approve it, keeping this device's signing key and fingerprint.\n" +
			"An admin's own key is switched at once. Secrets are post-quantum once every member has upgraded.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := a.UpgradeIdentity(cmd.Context())
			if err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, res, res.Warnings...)
			}
			cmd.Printf("Backend: %s\nAlgorithm: %s\nFingerprint: %s\n", res.Backend, res.Algorithm, res.Fingerprint)
			if res.Pending {
				cmd.Println("Ask an admin to run 'enbu member approve' and compare this fingerprint.")
			} else {
				cmd.Println("Switched to the post-quantum key and re-encrypted every environment.")
			}
			return nil
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
	return &cobra.Command{Use: "doctor", Short: "Diagnose identity backends, configuration, authentication, storage and workspace integrity", Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			d := a.Diagnose(cmd.Context())
			if jsonEnabled(cmd) {
				return writeJSON(cmd, d)
			}
			cmd.Printf("Hardware: %s\nDevice: %s\nAvailable: %t\n", d.Backend, d.Device, d.Available)
			if d.Reason != "" {
				cmd.Printf("Reason: %s\n", d.Reason)
			}
			cmd.Printf("OS keyring available: %t\n", d.KeyringAvailable)
			if d.KeyringReason != "" {
				cmd.Printf("OS keyring reason: %s\n", d.KeyringReason)
			}
			cmd.Printf("systemd-creds available: %t\n", d.CredsAvailable)
			if d.CredsReason != "" {
				cmd.Printf("systemd-creds reason: %s\n", d.CredsReason)
			}
			cmd.Printf("Software fallback available: %t\n", d.FallbackAvailable)
			if d.Fallback != "" {
				cmd.Printf("Software fallback: %s\n", d.Fallback)
			}
			if d.FallbackReason != "" {
				cmd.Printf("Fallback: %s\n", d.FallbackReason)
			}
			for _, check := range d.Checks {
				name := check.Name
				if check.Environment != "" {
					name += " [" + check.Environment + "]"
				}
				cmd.Printf("%s: %s — %s", name, check.Status, check.Message)
				if check.Code != "" {
					cmd.Printf(" (%s)", check.Code)
				}
				cmd.Println()
			}
			cmd.Printf("Healthy: %t\n", d.Healthy)
			return nil
		}}
}

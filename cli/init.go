package cli

import (
	"fmt"
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/spf13/cobra"
)

func newInitCommand(a *app.App) *cobra.Command {
	var settings config.StorageConfig
	var acceptNewGenesis bool
	cmd := &cobra.Command{Use: "init", Short: "Initialize or join a workspace", Args: appArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.LoadProjectFrom(a.RepositoryDir)
		if err == nil {
			settings = cfg.Storage
		}
		if cmd.Flags().Changed("region") {
			settings.Region, _ = cmd.Flags().GetString("region")
		}
		if cmd.Flags().Changed("endpoint") {
			settings.Endpoint, _ = cmd.Flags().GetString("endpoint")
		}
		if cmd.Flags().Changed("path-style") {
			settings.PathStyle, _ = cmd.Flags().GetBool("path-style")
		}
		if cmd.Flags().Changed("plain-http") {
			settings.PlainHTTP, _ = cmd.Flags().GetBool("plain-http")
		}
		if a.StorageURL != "" {
			settings.URL = a.StorageURL
		}
		result, err := a.InitializeRepository(cmd.Context(), app.InitOptions{Storage: &settings, AcceptNewGenesis: acceptNewGenesis})
		if err != nil {
			return err
		}
		if jsonEnabled(cmd) {
			return writeJSON(cmd, result, result.Warnings...)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Workspace: %s\nStorage: %s\nRecipient: %s\n", result.WorkspaceID, result.Storage, result.PublicKey)
		if result.ReplacedGenesis != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Trust root replaced:\n  was %s\n  now %s\n", result.ReplacedGenesis, result.ControlGenesis)
		}
		for _, warning := range result.Warnings {
			cmd.PrintErrln(warning)
		}
		if hint := ghcrAccessHint(result); hint != "" {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), hint)
		}
		if result.Pending {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Waiting for approval. Ask an admin to run 'enbu member approve' and confirm this fingerprint:\n  %s\n", result.Fingerprint)
		} else if result.CanDecrypt != nil && !*result.CanDecrypt {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Ask an existing member to run 'enbu sync', then run 'enbu pull'.")
		}
		return nil
	}}
	cmd.Flags().StringVar(&settings.Region, "region", "", "S3 region")
	cmd.Flags().StringVar(&settings.Endpoint, "endpoint", "", "S3 service endpoint")
	cmd.Flags().BoolVar(&settings.PathStyle, "path-style", false, "Use S3 path-style addressing")
	cmd.Flags().BoolVar(&settings.PlainHTTP, "plain-http", false, "Use HTTP for a local OCI registry")
	cmd.Flags().BoolVar(&acceptNewGenesis, "accept-new-genesis", false, "Trust the control_genesis in enbu.toml although this device trusted another one (only after an admin confirms the workspace was re-created)")
	return cmd
}

// ghcrAccessHint tells the founder of a GHCR workspace how to let teammates
// in: GHCR creates the package private to its creator, so others cannot even
// leave a join request until it inherits the repository's access.
func ghcrAccessHint(result *app.InitResult) string {
	path, ok := strings.CutPrefix(result.Storage, "oci://ghcr.io/")
	if !result.Founded || !ok {
		return ""
	}
	owner, pkg, _ := strings.Cut(path, "/")
	return fmt.Sprintf("GHCR created the package %s private to you. So that teammates can join, open it on GitHub (%s → Packages → %s → Package settings), connect this repository and turn on 'Inherit access from repository'.", pkg, owner, pkg)
}

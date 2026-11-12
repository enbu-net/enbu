package cli

import (
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/spf13/cobra"
)

func newStorageCommand(a *app.App) *cobra.Command {
	cmd := &cobra.Command{Use: "storage", Short: "Show or migrate workspace storage", Args: appArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.LoadProjectFrom(a.RepositoryDir)
		if err != nil {
			return err
		}
		if jsonEnabled(cmd) {
			return writeJSON(cmd, cfg.Storage)
		}
		cmd.Println(cfg.Storage.URL)
		return nil
	}}
	var settings config.StorageConfig
	var paused bool
	migrate := &cobra.Command{Use: "migrate URL", Short: "Copy encrypted history and switch storage", Long: `Pause writes by every team member before migrating. Copies verified encrypted
history, checks the copy, and updates enbu.toml only after success. The old
storage is retained. Share the updated enbu.toml with every member before
resuming writes. The destination must be empty or contain only a partial copy
from this migration.`, Args: appArgs(cobra.ExactArgs(1)), RunE: func(cmd *cobra.Command, args []string) error {
		if !paused {
			return invalidArgument("pause team writes, then pass --writes-paused", nil)
		}
		settings.URL = args[0]
		if err := a.ChangeStorage(cmd.Context(), settings); err != nil {
			return err
		}
		if jsonEnabled(cmd) {
			return writeJSON(cmd, settings)
		}
		cmd.Println("Storage migrated. Share the updated enbu.toml with every member before resuming writes. The old storage was retained.")
		return nil
	}}
	migrate.Flags().BoolVar(&paused, "writes-paused", false, "Confirm that every team member has paused writes")
	migrate.Flags().StringVar(&settings.Region, "region", "", "S3 region")
	migrate.Flags().StringVar(&settings.Endpoint, "endpoint", "", "S3 service endpoint")
	migrate.Flags().BoolVar(&settings.PathStyle, "path-style", false, "Use S3 path-style addressing")
	migrate.Flags().BoolVar(&settings.PlainHTTP, "plain-http", false, "Use HTTP for a local OCI registry")
	cmd.AddCommand(migrate)
	return cmd
}

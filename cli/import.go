package cli

import (
	"io"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/schema/secretmap"
	"github.com/spf13/cobra"
)

func newImportCommand(a *app.App) *cobra.Command {
	var envName string
	var overwrite bool

	cmd := &cobra.Command{
		Use:   "import FILE",
		Short: "Add every variable of a .env file as secrets",
		Long: `Reads the dotenv file FILE ("-" for stdin) and adds its variables to the
current environment in one signed state. A variable that already exists with
the same value is left alone; one with another value stops the import unless
--overwrite is given.`,
		Args: appArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			var data []byte
			var err error
			if path == "-" {
				data, err = io.ReadAll(cmd.InOrStdin())
			} else {
				if a.RepositoryDir != "" && !filepath.IsAbs(path) {
					path = filepath.Join(a.RepositoryDir, path)
				}
				data, err = os.ReadFile(path)
			}
			if err != nil {
				return invalidArgument("reading "+path, err)
			}
			secrets, err := secretmap.ImportDotenv(data)
			if err != nil {
				return invalidArgument("not a valid dotenv file: "+path, err)
			}
			result, err := a.ImportSecrets(cmd.Context(), envName, secrets, overwrite)
			if err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"action":      "import",
					"environment": result.Environment,
					"added":       result.Added,
					"updated":     result.Updated,
					"unchanged":   result.Unchanged,
				})
			}
			cmd.Printf("✓ Imported %d secret(s) into %s (%d added, %d updated, %d unchanged)\n",
				len(result.Added)+len(result.Updated), result.Environment, len(result.Added), len(result.Updated), len(result.Unchanged))
			return nil
		},
	}

	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Replace secrets that exist with another value")
	return cmd
}

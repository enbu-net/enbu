package cli

import (
	"bytes"
	"fmt"

	"github.com/spf13/cobra"
)

func newCompletionCommand(root *cobra.Command) *cobra.Command {
	var noDescriptions bool
	cmd := &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate the autocompletion script for the specified shell",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			var output bytes.Buffer
			var err error
			switch args[0] {
			case "bash":
				err = root.GenBashCompletionV2(&output, !noDescriptions)
			case "zsh":
				if noDescriptions {
					err = root.GenZshCompletionNoDesc(&output)
				} else {
					err = root.GenZshCompletion(&output)
				}
			case "fish":
				err = root.GenFishCompletion(&output, !noDescriptions)
			case "powershell":
				if noDescriptions {
					err = root.GenPowerShellCompletion(&output)
				} else {
					err = root.GenPowerShellCompletionWithDesc(&output)
				}
			default:
				return fmt.Errorf("unsupported shell %q", args[0])
			}
			if err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"shell":  args[0],
					"script": output.String(),
				})
			}
			_, err = cmd.OutOrStdout().Write(output.Bytes())
			return err
		},
	}
	cmd.Flags().BoolVar(&noDescriptions, "no-descriptions", false, "disable completion descriptions")
	return cmd
}

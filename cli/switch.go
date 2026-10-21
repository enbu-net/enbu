package cli

import (
	"sort"

	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func newSwitchCommand(a *app.App) *cobra.Command {
	var (
		create           bool
		delete           bool
		purge            bool
		purgeIncarnation string
		list             bool
		moveOld          string
		moveNew          string
		doMove           bool
	)

	cmd := &cobra.Command{
		Use:   "switch [env]",
		Short: "Switch, create, or manage environments",
		Args:  appArgs(cobra.MaximumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if list {
				return runSwitchList(cmd, a)
			}

			if purgeIncarnation != "" {
				n, err := a.PurgeIncarnation(cmd.Context(), purgeIncarnation)
				if err != nil {
					return err
				}
				if jsonEnabled(cmd) {
					return writeJSON(cmd, map[string]any{"action": "purge", "incarnation": purgeIncarnation, "purged": n})
				}
				cmd.Printf("Deleted %d stored revision(s)\n", n)
				return nil
			}

			if doMove {
				if err := a.RenameEnvironment(moveOld, moveNew); err != nil {
					return err
				}
				if jsonEnabled(cmd) {
					return writeJSON(cmd, map[string]any{
						"action":   "rename",
						"old_name": moveOld,
						"new_name": moveNew,
					})
				}
				cmd.Printf("Renamed '%s' to '%s'\n", moveOld, moveNew)
				return nil
			}

			if delete {
				if len(args) == 0 {
					return invalidArgument("environment name required for --delete", nil)
				}
				purged, incarnation := 0, ""
				if purge {
					n, err := a.DeleteEnvironmentPurging(cmd.Context(), args[0])
					if err != nil {
						return err
					}
					purged = n
				} else {
					incarnation = incarnationOf(a, args[0])
					if err := a.DeleteEnvironment(args[0]); err != nil {
						return err
					}
				}
				if jsonEnabled(cmd) {
					out := map[string]any{"action": "delete", "environment": args[0], "purged": purged}
					if incarnation != "" {
						out["incarnation"] = incarnation
					}
					return writeJSON(cmd, out)
				}
				cmd.Printf("Deleted environment '%s'\n", args[0])
				if purge {
					cmd.Printf("Deleted %d stored revision(s)\n", purged)
				} else if incarnation != "" {
					cmd.Printf("Its stored revisions remain. To delete them later (admin only): enbu switch --purge-incarnation %s\n", incarnation)
				}
				return nil
			}

			if len(args) == 0 {
				return runSwitchList(cmd, a)
			}

			name := args[0]

			if create {
				if err := a.CreateEnvironment(name); err != nil {
					return err
				}
				if jsonEnabled(cmd) {
					return writeJSON(cmd, map[string]any{
						"action":      "create",
						"environment": name,
					})
				}
				cmd.Printf("Created and switched to '%s'\n", name)
				return nil
			}

			if name == "-" {
				target, err := a.SwitchPrevious()
				if err != nil {
					return err
				}
				if jsonEnabled(cmd) {
					return writeJSON(cmd, map[string]any{
						"action":      "switch",
						"environment": target,
					})
				}
				cmd.Printf("Switched to '%s'\n", target)
				return nil
			}

			if err := a.SwitchEnvironment(name); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"action":      "switch",
					"environment": name,
				})
			}
			cmd.Printf("Switched to '%s'\n", name)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&create, "create", "c", false, "Create a new environment and switch to it")
	cmd.Flags().BoolVarP(&delete, "delete", "d", false, "Delete an environment")
	cmd.Flags().StringVar(&purgeIncarnation, "purge-incarnation", "", "Delete the stored revisions of an environment that was deleted without --purge (admin only)")
	cmd.Flags().BoolVar(&purge, "purge", false, "With --delete, also delete the environment's stored revisions (admin only)")
	cmd.Flags().BoolVarP(&list, "list", "l", false, "List all environments")
	cmd.Flags().StringVarP(&moveOld, "move", "m", "", "Rename an environment (old name)")

	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if moveOld != "" {
			doMove = true
			if len(args) == 0 {
				return invalidArgument("new name required: enbu switch -m <old> <new>", nil)
			}
			moveNew = args[0]
		}
		return nil
	}

	return cmd
}

func runSwitchList(cmd *cobra.Command, a *app.App) error {
	envs, err := a.ListEnvironments()
	if err != nil {
		return err
	}

	sort.Slice(envs, func(i, j int) bool { return envs[i].Name < envs[j].Name })

	if jsonEnabled(cmd) {
		return writeJSON(cmd, map[string]any{
			"action":       "list",
			"environments": envs,
		})
	}

	for _, env := range envs {
		if env.IsCurrent {
			cmd.Printf("* %s\n", env.Name)
		} else {
			cmd.Printf("  %s\n", env.Name)
		}
	}
	return nil
}

// incarnationOf is what names an environment's stored revisions, so it can be
// shown before the environment is forgotten.
func incarnationOf(a *app.App, name string) string {
	envs, err := a.ListEnvironments()
	if err != nil {
		return ""
	}
	for _, e := range envs {
		if e.Name == name {
			return e.Incarnation
		}
	}
	return ""
}

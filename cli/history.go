package cli

import (
	"strconv"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func newHistoryCommand(a *app.App) *cobra.Command {
	var env string

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List history entries",
		Args:  appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := a.ListHistory(cmd.Context(), env)
			if err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				result := make([]historyEntryResponse, 0, len(entries))
				for _, entry := range entries {
					result = append(result, historyEntryResponse{
						Index:     entry.Index,
						Timestamp: entry.Timestamp,
						Tag:       entry.Tag,
						Latest:    entry.Index == len(entries),
					})
				}
				return writeJSON(cmd, map[string]any{
					"environment": resolvedEnvironmentName(a, env),
					"entries":     result,
				})
			}
			if len(entries) == 0 {
				cmd.Println("No history found.")
				return nil
			}
			// The tag is a storage name; people refer to entries by number.
			cmd.Printf("%-4s %s\n", "#", "TIMESTAMP")
			for _, e := range entries {
				latest := ""
				if e.Index == len(entries) {
					latest = "  (latest)"
				}
				cmd.Printf("%-4d %s%s\n", e.Index, e.Timestamp.Local().Format(time.DateTime), latest)
			}
			return nil
		},
	}

	// `enbu history` alone lists, like `git log`.
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List and restore secret history",
		Args:  appArgs(cobra.NoArgs),
		RunE:  listCmd.RunE,
	}
	cmd.Flags().StringVarP(&env, "env", "e", "", "Environment name")

	diffCmd := &cobra.Command{
		Use:   "diff <from> <to>",
		Short: "Show diff between two history entries",
		Args:  appArgs(cobra.ExactArgs(2)),
		RunE: func(cmd *cobra.Command, args []string) error {
			from, err := strconv.Atoi(args[0])
			if err != nil {
				return invalidArgument("invalid version number "+args[0], err)
			}
			to, err := strconv.Atoi(args[1])
			if err != nil {
				return invalidArgument("invalid version number "+args[1], err)
			}

			diff, err := a.DiffHistory(cmd.Context(), env, from, to)
			if err != nil {
				return err
			}

			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"environment": resolvedEnvironmentName(a, env),
					"from":        from,
					"to":          to,
					"added":       nonNilStrings(diff.Added),
					"removed":     nonNilStrings(diff.Removed),
					"modified":    nonNilStrings(diff.Modified),
				})
			}

			if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Modified) == 0 {
				cmd.Println("No differences.")
				return nil
			}

			for _, k := range diff.Added {
				cmd.Printf("+ %s\n", k)
			}
			for _, k := range diff.Removed {
				cmd.Printf("- %s\n", k)
			}
			for _, k := range diff.Modified {
				cmd.Printf("~ %s\n", k)
			}
			return nil
		},
	}

	restoreCmd := &cobra.Command{
		Use:   "restore <version>",
		Short: "Restore secrets to a previous history entry",
		Args:  appArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			idx, err := strconv.Atoi(args[0])
			if err != nil {
				return invalidArgument("invalid version number "+args[0], err)
			}
			if err := a.RestoreHistory(cmd.Context(), env, idx); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"environment": resolvedEnvironmentName(a, env),
					"version":     idx,
				})
			}
			return nil
		},
	}

	var keep int
	compactCmd := &cobra.Command{
		Use:   "compact --keep N",
		Short: "Delete stored revisions older than the latest N (admin only)",
		Long: "Delete the stored revisions of an environment older than the latest N, so storage\n" +
			"and reads stop growing with its history. The deleted versions leave the history.\n" +
			"Other devices accept the deletion through a signed record. Admin only, and only on\n" +
			"storage that can delete.",
		Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("keep") {
				return invalidArgument("--keep is required: how many of the latest revisions to keep", nil)
			}
			result, err := a.CompactHistory(cmd.Context(), env, keep)
			if err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"environment": resolvedEnvironmentName(a, env),
					"kept":        result.Kept,
					"removed":     result.Removed,
				})
			}
			cmd.Printf("Deleted %d stored revision(s), kept %d\n", result.Removed, result.Kept)
			return nil
		},
	}
	compactCmd.Flags().IntVar(&keep, "keep", 0, "How many of the latest revisions to keep")

	for _, sub := range []*cobra.Command{listCmd, diffCmd, restoreCmd, compactCmd} {
		sub.Flags().StringVarP(&env, "env", "e", "", "Environment name")
		cmd.AddCommand(sub)
	}

	return cmd
}

type historyEntryResponse struct {
	Index     int       `json:"index"`
	Timestamp time.Time `json:"timestamp"`
	Tag       string    `json:"tag"`
	Latest    bool      `json:"latest"`
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

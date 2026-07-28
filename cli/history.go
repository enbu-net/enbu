package cli

import (
	"fmt"
	"strconv"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/spf13/cobra"
)

func newHistoryCommand(a *app.App) *cobra.Command {
	var env string

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Manage secret history",
		RunE: func(cmd *cobra.Command, args []string) error {
			return renderHelp(cmd)
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List history entries",
		Args:  cobra.NoArgs,
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
			cmd.Printf("%-4s %-20s %s\n", "#", "TIMESTAMP", "TAG")
			for _, e := range entries {
				latest := ""
				if e.Index == len(entries) {
					latest = " (latest)"
				}
				cmd.Printf("%-4d %-20s %s%s\n", e.Index, e.Timestamp.Format("2006-01-02 15:04:05"), e.Tag, latest)
			}
			return nil
		},
	}

	diffCmd := &cobra.Command{
		Use:   "diff <from> <to>",
		Short: "Show diff between two history entries",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			from, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid version number %q", args[0])
			}
			to, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("invalid version number %q", args[1])
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
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			idx, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid version number %q", args[0])
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

	for _, sub := range []*cobra.Command{listCmd, diffCmd, restoreCmd} {
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

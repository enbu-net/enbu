package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/spf13/cobra"
)

func newResolveCommand(a *app.App) *cobra.Command {
	var (
		envName string
		seen    string
		picks   []string
		deletes []string
	)
	cmd := &cobra.Command{
		Use:   "resolve [KEY=VALUE...]",
		Short: "Choose between secrets that were changed at the same time",
		Long: `When two people change the same secret at the same time, nothing is lost and
nothing is chosen for them: reading and writing stop until someone decides.

Without options, resolve lists the conflicts and the candidates for each key.
To settle them, give a decision for every conflicted key:

  enbu resolve --seen ID KEY=VALUE      use this value
  enbu resolve --seen ID --pick KEY=N   use the Nth candidate of the list
  enbu resolve --seen ID --delete KEY   remove the key

ID is printed by the listing. If anyone has written since, the ID no longer
matches and nothing is changed, so a value you have not seen is never replaced.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := a.ListConflicts(cmd.Context(), envName)
			if err != nil {
				return err
			}
			if len(args)+len(picks)+len(deletes) == 0 {
				return printConflicts(cmd, a, envName, set)
			}
			if seen != set.ID {
				return apperr.New(apperr.CodeConflict, "the conflicts are not the ones you looked at (or --seen is missing); run 'enbu resolve' to see them again", nil)
			}
			choices, err := parseChoices(set.Conflicts, args, picks, deletes)
			if err != nil {
				return err
			}
			// The heads just listed are the ones the choices were made against.
			if err := a.ResolveSecrets(cmd.Context(), envName, set.Heads, choices); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				keys := make([]string, 0, len(choices))
				for k := range choices {
					keys = append(keys, k)
				}
				return writeJSON(cmd, map[string]any{"action": "resolve", "environment": resolvedEnvironmentName(a, envName), "keys": keys})
			}
			cmd.Printf("✓ Resolved %d secret(s)\n", len(choices))
			return nil
		},
	}
	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	cmd.Flags().StringVar(&seen, "seen", "", "ID of the conflict listing the decisions were made from")
	cmd.Flags().StringArrayVar(&picks, "pick", nil, "Use the Nth candidate of a key, as KEY=N")
	cmd.Flags().StringArrayVar(&deletes, "delete", nil, "Delete a conflicted key")
	return cmd
}

func printConflicts(cmd *cobra.Command, a *app.App, envName string, set *app.ConflictSet) error {
	conflicts := set.Conflicts
	if jsonEnabled(cmd) {
		return writeJSON(cmd, map[string]any{"environment": resolvedEnvironmentName(a, envName), "id": set.ID, "conflicts": conflicts})
	}
	if len(conflicts) == 0 {
		cmd.Println("No conflicts")
		return nil
	}
	for _, c := range conflicts {
		cmd.Printf("%s was changed at the same time:\n", c.Key)
		for i, cand := range c.Candidates {
			if cand.Deleted {
				cmd.Printf("  %d) (deleted)\n", i+1)
			} else {
				cmd.Printf("  %d) %s\n", i+1, cand.Value)
			}
		}
	}
	cmd.Printf("Decide every key, for example: enbu resolve --seen %s KEY=VALUE (or --pick KEY=N, --delete KEY)\n", set.ID)
	return nil
}

func parseChoices(conflicts []app.SecretConflict, values, picks, deletes []string) (map[string]app.SecretChoice, error) {
	byKey := map[string]app.SecretConflict{}
	for _, c := range conflicts {
		byKey[c.Key] = c
	}
	choices := map[string]app.SecretChoice{}
	set := func(key string, choice app.SecretChoice) error {
		if _, ok := byKey[key]; !ok {
			return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("%s has no conflict to resolve", key), apperr.Params{"key": key})
		}
		if _, dup := choices[key]; dup {
			return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("%s was decided twice", key), apperr.Params{"key": key})
		}
		choices[key] = choice
		return nil
	}
	for _, kv := range values {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("expected KEY=VALUE, got %q", kv), nil)
		}
		if err := set(key, app.SecretChoice{Value: value}); err != nil {
			return nil, err
		}
	}
	for _, kn := range picks {
		key, n, ok := strings.Cut(kn, "=")
		idx, err := strconv.Atoi(n)
		c, known := byKey[key]
		if !ok || err != nil || !known || idx < 1 || idx > len(c.Candidates) {
			return nil, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("--pick %q does not name a candidate of a conflicted key", kn), nil)
		}
		cand := c.Candidates[idx-1]
		if err := set(key, app.SecretChoice{Value: cand.Value, Delete: cand.Deleted}); err != nil {
			return nil, err
		}
	}
	for _, key := range deletes {
		if err := set(key, app.SecretChoice{Delete: true}); err != nil {
			return nil, err
		}
	}
	return choices, nil
}

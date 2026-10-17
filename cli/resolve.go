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

  enbu resolve KEY=VALUE      use this value
  enbu resolve --pick KEY=N   use the Nth candidate of the list
  enbu resolve --delete KEY   remove the key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			conflicts, err := a.ListConflicts(cmd.Context(), envName)
			if err != nil {
				return err
			}
			if len(args)+len(picks)+len(deletes) == 0 {
				return printConflicts(cmd, a, envName, conflicts)
			}
			choices, err := parseChoices(conflicts, args, picks, deletes)
			if err != nil {
				return err
			}
			if err := a.ResolveSecrets(cmd.Context(), envName, choices); err != nil {
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
	cmd.Flags().StringArrayVar(&picks, "pick", nil, "Use the Nth candidate of a key, as KEY=N")
	cmd.Flags().StringArrayVar(&deletes, "delete", nil, "Delete a conflicted key")
	return cmd
}

func printConflicts(cmd *cobra.Command, a *app.App, envName string, conflicts []app.SecretConflict) error {
	if jsonEnabled(cmd) {
		return writeJSON(cmd, map[string]any{"environment": resolvedEnvironmentName(a, envName), "conflicts": conflicts})
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
	cmd.Println("Decide every key with: enbu resolve KEY=VALUE, --pick KEY=N or --delete KEY")
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

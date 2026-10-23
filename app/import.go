package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
)

// ImportResult names what one import did to an environment.
type ImportResult struct {
	Environment string   `json:"environment"`
	Added       []string `json:"added"`
	Updated     []string `json:"updated"`
	Unchanged   []string `json:"unchanged"`
}

// ImportSecrets adds every key of secrets to env in one signed state. A key
// that already exists with the same value is left alone; one with another
// value is refused unless overwrite is set, so an import never changes a
// secret nobody meant to change.
func (a *App) ImportSecrets(ctx context.Context, env string, secrets map[string]string, overwrite bool) (result *ImportResult, err error) {
	defer apperr.NormalizeInto(&err)
	if len(secrets) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "nothing to import", nil)
	}
	resolved, err := a.resolveEnvironment(env)
	if err != nil {
		return nil, err
	}
	result = &ImportResult{Environment: resolved.Name, Added: []string{}, Updated: []string{}, Unchanged: []string{}}
	err = a.changeSecret(ctx, env, "import", func(current map[string]string) error {
		result.Added, result.Updated, result.Unchanged = result.Added[:0], result.Updated[:0], result.Unchanged[:0]
		var conflicts []string
		for key, value := range secrets {
			old, exists := current[key]
			switch {
			case !exists:
				result.Added = append(result.Added, key)
			case old == value:
				result.Unchanged = append(result.Unchanged, key)
			case overwrite:
				result.Updated = append(result.Updated, key)
			default:
				conflicts = append(conflicts, key)
			}
		}
		if len(conflicts) > 0 {
			sort.Strings(conflicts)
			return apperr.New(apperr.CodeSecretExists,
				fmt.Sprintf("%d secret(s) already exist with another value (use --overwrite to replace them): %s", len(conflicts), strings.Join(conflicts, ", ")),
				// key fills the shared secret_already_exists message; keys is for callers.
				apperr.Params{"key": strings.Join(conflicts, ", "), "keys": strings.Join(conflicts, ",")})
		}
		for key, value := range secrets {
			current[key] = value
		}
		if len(result.Added)+len(result.Updated) == 0 {
			return errNoChange
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(result.Added)
	sort.Strings(result.Updated)
	sort.Strings(result.Unchanged)
	return result, nil
}

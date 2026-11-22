package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/dotenv"
)

// ImportResult names what one import did to an environment.
type ImportResult struct {
	Environment string   `json:"environment"`
	Added       []string `json:"added"`
	Updated     []string `json:"updated"`
	Unchanged   []string `json:"unchanged"`
}

// ImportTarget pins a file chosen asynchronously to the lineage shown when
// the user picked it. A CLI import resolves its environment in one operation.
type ImportTarget struct {
	WorkspaceID string `json:"workspace_id"`
	Environment string `json:"environment"`
	Incarnation string `json:"incarnation"`
}

// ImportDotenv adds every variable of a dotenv file's content to env, as
// ImportSecrets does.
func (a *App) ImportDotenv(ctx context.Context, env string, content []byte, overwrite bool, target ...ImportTarget) (result *ImportResult, err error) {
	defer apperr.NormalizeInto(&err)
	secrets, err := dotenv.Parse(content)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument, "not a valid dotenv file (save it as UTF-8)", err, nil)
	}
	var expected *ImportTarget
	if len(target) != 0 {
		expected = &target[0]
	}
	return a.importSecrets(ctx, env, secrets, overwrite, expected)
}

// ImportSecrets adds every key of secrets to env in one signed state. A key
// that already exists with the same value is left alone; one with another
// value is refused unless overwrite is set, so an import never changes a
// secret nobody meant to change.
func (a *App) ImportSecrets(ctx context.Context, env string, secrets map[string]string, overwrite bool) (result *ImportResult, err error) {
	defer apperr.NormalizeInto(&err)
	return a.importSecrets(ctx, env, secrets, overwrite, nil)
}

func (a *App) importSecrets(ctx context.Context, env string, secrets map[string]string, overwrite bool, expected *ImportTarget) (*ImportResult, error) {
	if len(secrets) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "nothing to import", nil)
	}
	s, resolved, err := a.openEnvironment(ctx, env)
	if err != nil {
		return nil, err
	}
	if expected != nil && (expected.WorkspaceID != s.workspace ||
		expected.Environment != resolved.Name || expected.Incarnation != s.cfg.Environments[resolved.Name].Incarnation) {
		s.Close()
		return nil, apperr.New(apperr.CodeConflict, "the import target changed; select the file again", nil)
	}
	result := &ImportResult{Environment: resolved.Name, Added: []string{}, Updated: []string{}, Unchanged: []string{}}
	err = a.changeResource(ctx, s, s.resource(resolved.Name), "import", nil, nil, func(current map[string]string) error {
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
			if len(conflicts) > 1 {
				return apperr.New(apperr.CodeImportConflict, "import conflicts", apperr.Params{"count": fmt.Sprint(len(conflicts)), "keys": strings.Join(conflicts, ", ")})
			}
			return apperr.New(apperr.CodeSecretExists,
				fmt.Sprintf("%d secret(s) already exist with another value (use --overwrite to replace them): %s", len(conflicts), strings.Join(conflicts, ", ")),
				apperr.Params{"key": strings.Join(conflicts, ", ")})
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

package cli

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/spf13/cobra"
)

func newRunCommand(a *app.App) *cobra.Command {
	var envName string
	var preserveEnv bool

	cmd := &cobra.Command{
		Use:   "run [flags] -- COMMAND [ARGS...]",
		Short: "Run a command with the secrets in its environment",
		Long: `Decrypts the environment's secrets and runs COMMAND with them as environment
variables, without writing a .env file. Secrets replace variables of the same
name unless --preserve-env is given. The command's exit status is returned.`,
		Args: appArgs(cobra.MinimumNArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonEnabled(cmd) {
				return invalidArgument("--json cannot be used with run: the command owns stdout", nil)
			}
			result, err := a.PullSecretsData(cmd.Context(), envName)
			if err != nil {
				return err
			}
			child := exec.Command(args[0], args[1:]...)
			child.Env = mergedEnv(os.Environ(), result.Secrets, preserveEnv)
			child.Stdin = cmd.InOrStdin()
			child.Stdout = cmd.OutOrStdout()
			child.Stderr = cmd.ErrOrStderr()
			// Ctrl-C goes to the whole foreground process group; let the
			// command decide what it means and report how it ended.
			signal.Ignore(os.Interrupt)
			defer signal.Reset(os.Interrupt)
			err = child.Run()
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return &apperr.ExitError{Code: exit.ExitCode()}
			}
			if err != nil {
				return invalidArgument("running "+args[0], err)
			}
			return nil
		},
	}
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringVarP(&envName, "env", "e", "", "Environment to use (overrides current)")
	cmd.Flags().BoolVar(&preserveEnv, "preserve-env", false, "Keep variables already set in the environment over secrets of the same name")
	return cmd
}

// mergedEnv is base with secrets applied. Secrets win over base unless
// preserve is set. The result is sorted so it is stable.
func mergedEnv(base []string, secrets map[string]string, preserve bool) []string {
	env := map[string]string{}
	for _, kv := range base {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	for k, v := range secrets {
		if _, set := env[k]; set && preserve {
			continue
		}
		env[k] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

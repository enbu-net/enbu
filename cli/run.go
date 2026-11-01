package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"

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
			release := bindToEnbu(child)
			defer release()
			child.Env = mergedEnv(os.Environ(), result.Secrets, preserveEnv)
			child.Stdin = cmd.InOrStdin()
			child.Stdout = cmd.OutOrStdout()
			child.Stderr = cmd.ErrOrStderr()
			// Ctrl-C reaches the whole foreground process group, so the
			// command gets it directly and decides what it means; enbu only
			// stays alive to report how it ended. Termination signals sent
			// to enbu alone are passed on, so the command, which holds the
			// secrets, is not left running on its own.
			signals := make(chan os.Signal, 1)
			signal.Notify(signals, append([]os.Signal{os.Interrupt}, forwardedSignals...)...)
			defer signal.Stop(signals)
			if err := child.Start(); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Error: running %s: %v\n", args[0], err)
				return &apperr.ExitError{Code: startFailureCode(err)}
			}
			done := make(chan struct{})
			go func() {
				for {
					select {
					case s := <-signals:
						if s != os.Interrupt {
							_ = child.Process.Signal(s)
						}
					case <-done:
						return
					}
				}
			}()
			err = child.Wait()
			close(done)
			if code, ok := exitCode(err); ok {
				return &apperr.ExitError{Code: code}
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

// forwardedSignals are passed on to the command when enbu receives them.
var forwardedSignals = []os.Signal{syscall.SIGTERM, syscall.SIGHUP}

// exitCode is the status a shell would report for the command: its exit
// code, or 128 plus the signal that ended it.
func exitCode(err error) (int, bool) {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return 0, false
	}
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), true
	}
	return exit.ExitCode(), true
}

// startFailureCode follows the shell: 127 when the command is not found,
// 126 when it was found but could not be run.
func startFailureCode(err error) int {
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
		return 127
	}
	return 126
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

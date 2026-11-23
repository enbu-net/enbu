package cli

import (
	"context"
	"strings"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/spf13/cobra"
)

type authLoginDeps struct {
	login       func(context.Context, auth.DevicePrompter) (*auth.StoredToken, error)
	openBrowser func(string) error
}

type authStatusDeps struct {
	loadToken     func() (*auth.StoredToken, error)
	accounts      func() ([]string, string, error)
	identityStore app.IdentityStore
}

func newAuthCommand(a *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage authentication with GitHub",
		RunE: func(cmd *cobra.Command, args []string) error {
			return renderHelp(cmd)
		},
	}

	cmd.AddCommand(
		newAuthLoginCommand(),
		newAuthLogoutCommand(),
		newAuthSwitchCommand(),
		newAuthStatusCommand(a),
		newAuthMaintenanceCommand(false),
		newAuthMaintenanceCommand(true),
	)

	return cmd
}

func newAuthLoginCommand() *cobra.Command {
	return newAuthLoginCommandWithDeps(authLoginDeps{
		login:       auth.Client{Clock: clock.New()}.Login,
		openBrowser: auth.OpenBrowser,
	})
}

func newAuthLoginCommandWithDeps(deps authLoginDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with GitHub, adding an account",
		Long: `Authenticate with GitHub through the Device Flow: enter the code shown at
github.com/login/device, from any browser, so this works over SSH too. The code
goes to stderr, so --json output stays clean. Signing in with another account
adds it beside the accounts already signed in and makes it the one in use;
switch back with 'enbu auth switch'.`,
		Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := auth.TokenFromEnvironment()
			var err error
			if token == nil {
				token, err = deps.login(cmd.Context(), func(device auth.DeviceAuthorization) error {
					cmd.PrintErrf("Enter the code %s at %s\n", device.UserCode, device.VerificationURI)
					if err := deps.openBrowser(device.VerificationURI); err != nil {
						cmd.PrintErrln("Could not open the browser automatically; open the URL above manually.")
					}
					cmd.PrintErrln("Waiting for authorization...")
					return nil
				})
			}
			if err != nil {
				return err
			}

			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"authenticated": true,
					"username":      token.Username,
				})
			}
			cmd.Printf("✓ Authenticated as: %s\n", token.Username)
			return nil
		},
	}
}

func newAuthLogoutCommand() *cobra.Command {
	return newAuthLogoutCommandWithDelete(auth.DeleteAccount)
}

func newAuthLogoutCommandWithDelete(deleteAccount func(login string) error) *cobra.Command {
	var login string
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Sign out of the GitHub account in use, or of --user",
		Args:  appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := deleteAccount(login); err != nil {
				return err
			}

			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"logged_out":            true,
					"private_key_preserved": true,
				})
			}
			cmd.Println("✓ Logged out successfully.")
			cmd.Println("  Note: Your repository Identity is preserved.")
			return nil
		},
	}
	cmd.Flags().StringVar(&login, "user", "", "GitHub login to sign out of (default: the account in use)")
	return cmd
}

func newAuthSwitchCommand() *cobra.Command {
	return newAuthSwitchCommandWithDeps(auth.SwitchAccount)
}

func newAuthSwitchCommandWithDeps(switchAccount func(login string) (*auth.StoredToken, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "switch LOGIN",
		Short: "Use another signed-in GitHub account",
		Long: `Use another GitHub account that 'enbu auth login' signed in with. The choice
belongs to enbu's data directory, so another XDG_DATA_HOME keeps its own.
GITHUB_TOKEN, when set, is used instead of any account.`,
		Args: appArgs(cobra.ExactArgs(1)),
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := switchAccount(args[0])
			if err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{"username": token.Username})
			}
			cmd.Printf("✓ Using GitHub account: %s\n", token.Username)
			return nil
		},
	}
}

func newAuthMaintenanceCommand(reset bool) *cobra.Command {
	use, short := "migrate", "Move saved GitHub accounts from the OS keyring to the TPM"
	operation := auth.MigrateCredentials
	if reset {
		use, short = "reset", "Reset GitHub accounts in the selected credential store"
		operation = auth.ResetCredentials
	}
	var yes bool
	cmd := &cobra.Command{
		Use: use, Short: short, Args: appArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if reset && !yes {
				return invalidArgument("reset removes all saved GitHub accounts from the selected store; pass --yes to confirm", nil)
			}
			if err := operation(); err != nil {
				return err
			}
			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]bool{"completed": true})
			}
			if reset {
				cmd.Println("GitHub credentials reset. Run 'enbu auth login' to sign in again.")
			} else {
				cmd.Println("GitHub credential migration complete.")
			}
			return nil
		},
	}
	if reset {
		cmd.Flags().BoolVar(&yes, "yes", false, "Confirm reset of accounts in the selected credential store")
	}
	return cmd
}

func newAuthStatusCommand(a *app.App) *cobra.Command {
	return newAuthStatusCommandWithDeps(a, authStatusDeps{
		loadToken:     auth.LoadToken,
		accounts:      auth.Accounts,
		identityStore: a.Identities,
	})
}

func newAuthStatusCommandWithDeps(a *app.App, deps authStatusDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication and environment status",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := deps.loadToken()
			if err != nil {
				if !apperr.Is(err, apperr.CodeNotAuthenticated) {
					return err
				}
				if jsonEnabled(cmd) {
					return writeJSON(cmd, map[string]any{
						"authenticated":      false,
						"username":           nil,
						"repository":         nil,
						"public_key":         nil,
						"config_initialized": nil,
					})
				}
				cmd.Println("Auth: not logged in")
				cmd.Println("  Run 'enbu auth login' to authenticate with GitHub")
				return nil
			}
			humanPrintf(cmd, "Auth: logged in as %s\n", token.Username)
			accounts := []string{}
			if deps.accounts != nil && auth.TokenFromEnvironment() == nil {
				if logins, _, err := deps.accounts(); err == nil && logins != nil {
					accounts = logins
				}
			}
			if len(accounts) > 1 {
				humanPrintf(cmd, "Accounts: %s (switch with 'enbu auth switch LOGIN')\n", strings.Join(accounts, ", "))
			}

			owner, repo, err := a.RepoDetector.LoadRepo()
			if err != nil {
				if jsonEnabled(cmd) {
					return writeJSON(cmd, map[string]any{
						"authenticated":      true,
						"username":           token.Username,
						"accounts":           accounts,
						"repository":         nil,
						"public_key":         nil,
						"config_initialized": nil,
					})
				}
				cmd.Println("Repo: not in a git repository")
				return nil
			}
			humanPrintf(cmd, "Repo: %s/%s\n", owner, repo)

			var publicKey any
			if deps.identityStore != nil {
				workspaceID, _ := a.WorkspaceID()
				info, err := deps.identityStore.Info(workspaceID)
				if err == nil {
					publicKey = info.Recipient
					humanPrintf(cmd, "Identity: %s\nKey: %s\n", info.Backend, info.Recipient)
				} else {
					humanPrintf(cmd, "Identity: not initialized (%v)\n", err)
				}
			}

			configInitialized := false
			if _, err := config.LoadProject(); err == nil {
				configInitialized = true
				humanPrintf(cmd, "Config: enbu.toml found\n")
			} else {
				humanPrintf(cmd, "Config: not initialized\n")
			}

			if jsonEnabled(cmd) {
				return writeJSON(cmd, map[string]any{
					"authenticated": true,
					"username":      token.Username,
					"accounts":      accounts,
					"repository": map[string]string{
						"owner": owner,
						"name":  repo,
					},
					"public_key":         publicKey,
					"config_initialized": configInitialized,
				})
			}

			return nil
		},
	}
}

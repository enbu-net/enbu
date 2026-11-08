package cli

import (
	"context"

	"github.com/enbu-net/enbu/app"
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
		newAuthStatusCommand(a),
	)

	return cmd
}

func newAuthLoginCommand() *cobra.Command {
	return newAuthLoginCommandWithDeps(authLoginDeps{
		login:       auth.Client{Clock: clock.New()}.Login,
		openBrowser: auth.OpenBrowser,
	})
}

// newAuthLoginCommandWithDeps signs in with the GitHub Device Flow. The code
// goes to stderr, so it is shown with --json too.
func newAuthLoginCommandWithDeps(deps authLoginDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate with GitHub",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := deps.login(cmd.Context(), func(device auth.DeviceAuthorization) error {
				cmd.PrintErrf("Enter the code %s at %s\n", device.UserCode, device.VerificationURI)
				if err := deps.openBrowser(device.VerificationURI); err != nil {
					cmd.PrintErrln("Could not open the browser automatically; open the URL above manually.")
				}
				cmd.PrintErrln("Waiting for authorization...")
				return nil
			})
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
	return newAuthLogoutCommandWithDelete(auth.DeleteToken)
}

func newAuthLogoutCommandWithDelete(deleteToken func() error) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove stored authentication token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := deleteToken(); err != nil {
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
}

func newAuthStatusCommand(a *app.App) *cobra.Command {
	return newAuthStatusCommandWithDeps(a, authStatusDeps{
		loadToken:     auth.LoadToken,
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

			owner, repo, err := a.RepoDetector.LoadRepo()
			if err != nil {
				if jsonEnabled(cmd) {
					return writeJSON(cmd, map[string]any{
						"authenticated":      true,
						"username":           token.Username,
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

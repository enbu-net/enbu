package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/winbridge"
	"github.com/spf13/cobra"
)

const defaultDeviceClientID = "Ov23li6nFmfdF4FW9ikd"

type authLoginDeps struct {
	browserLogin func(context.Context, auth.BrowserOpener) (*auth.StoredToken, error)
	deviceLogin  func(context.Context, string, auth.DevicePrompter) (*auth.StoredToken, error)
	openBrowser  auth.BrowserOpener
	// windows runs the login in the Windows enbu.exe instead, inside WSL:
	// the token goes to the Windows keyring and Windows opens the browser.
	windows func(ctx context.Context, cmd *cobra.Command, args ...string) error
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
	client := auth.Client{Clock: clock.New()}
	deps := authLoginDeps{
		browserLogin: client.Login,
		deviceLogin:  client.LoginDevice,
		openBrowser:  auth.OpenBrowser,
	}
	if inWSL() {
		deps.windows = runInWindows
	}
	return newAuthLoginCommandWithDeps(deps)
}

// runInWindows runs an enbu command in the Windows enbu.exe on this terminal.
// Windows prints its own errors, so a failure only carries the exit status.
// An enbu.exe that is missing or cannot start is identity_unavailable, as for
// every other key operation inside WSL.
func runInWindows(ctx context.Context, cmd *cobra.Command, args ...string) error {
	err := winbridge.RunWindows(ctx, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args...)
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return &apperr.ExitError{Code: exit.ExitCode()}
	}
	if err != nil {
		return apperr.Wrap(apperr.CodeIdentityUnavailable, "Inside WSL, enbu signs in through the Windows enbu.exe, which could not run: "+err.Error()+". Run enbu doctor.", err, nil)
	}
	return nil
}

func newAuthLoginCommandWithDeps(deps authLoginDeps) *cobra.Command {
	var deviceFlow bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with GitHub",
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonEnabled(cmd) && deviceFlow {
				return invalidArgument("--device cannot be used with --json", nil)
			}

			ctx := cmd.Context()
			if deps.windows != nil {
				args := []string{"auth", "login"}
				if deviceFlow {
					args = append(args, "--device")
				}
				if jsonEnabled(cmd) {
					args = append(args, "--json")
				}
				return deps.windows(ctx, cmd, args...)
			}

			humanPrintf(cmd, "Initiating GitHub authentication...\n")
			var token *auth.StoredToken
			var err error
			if deviceFlow {
				clientID := os.Getenv("ENBU_CLIENT_ID")
				if clientID == "" {
					clientID = defaultDeviceClientID
				}
				token, err = deps.deviceLogin(ctx, clientID, func(device auth.DeviceAuthorization) error {
					humanPrintf(cmd, "Code: %s\n", device.UserCode)
					humanPrintf(cmd, "Verification URL: %s\n", device.VerificationURI)
					if err := deps.openBrowser(device.VerificationURI); err != nil {
						humanErrorf(cmd, "Could not open the browser automatically; open the URL above manually.\n")
					} else {
						humanPrintf(cmd, "→ Opened in your browser.\n")
					}
					humanPrintf(cmd, "Waiting for authorization...\n")
					return nil
				})
			} else {
				token, err = deps.browserLogin(ctx, func(authorizeURL string) error {
					if err := deps.openBrowser(authorizeURL); err != nil {
						return err
					}
					humanPrintf(cmd, "→ Opened GitHub in your browser.\n")
					humanPrintf(cmd, "Waiting for authorization...\n")
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
	cmd.Flags().BoolVar(&deviceFlow, "device", false, "Authenticate with GitHub Device Flow")

	return cmd
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

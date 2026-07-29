package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/oci"
	gitprovider "github.com/enbu-net/enbu/pkg/provider/git"
	gh "github.com/enbu-net/enbu/pkg/provider/github"
	"github.com/spf13/cobra"
)

func newInitCommand(a *app.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize enbu for this repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			accessToken, username, err := a.TokenProvider.LoadToken()
			if err != nil {
				return err
			}

			owner, repo, err := a.RepoDetector.LoadRepo()
			if err != nil {
				return fmt.Errorf("detecting repository: %w (run inside a git repository)", err)
			}

			registryRef := fmt.Sprintf("%s/%s/%s-enbu", registryHost(a), strings.ToLower(owner), strings.ToLower(repo))
			result := initResponse{
				Repository: initRepositoryResponse{Owner: owner, Name: repo},
				Registry:   registryRef,
				NextSteps:  []string{},
			}
			var warnings []string

			projectCfg, err := config.LoadProject()
			configMissing := false
			if err != nil {
				if apperr.Is(err, apperr.CodeConfigNotFound) {
					configMissing = true
					projectCfg = config.NewProjectWithEnvironment(app.DefaultEnvironment)
				} else {
					return err
				}
			}

			repository, err := gitClient(a).Inspect(ctx, ".")
			if err != nil {
				return fmt.Errorf("finding repository root: %w", err)
			}
			if !repository.HasGit {
				return fmt.Errorf("finding repository root: not in a git repository")
			}
			repoRoot := repository.Root
			updateGitignore := func() {
				if err := ensureProjectGitignore(repoRoot, projectCfg); err != nil {
					warnings = append(warnings, fmt.Sprintf("failed to update .gitignore: %v", err))
					humanErrorf(cmd, "Warning: failed to update .gitignore: %v\n", err)
				} else {
					result.GitignoreUpdated = true
					humanPrintf(cmd, "✓ Updated .gitignore\n")
				}
			}

			existingTags, err := a.Registry.ListTags(ctx, registryRef, accessToken)
			if err != nil && !app.IsNotFoundError(err) {
				return fmt.Errorf("checking existing setup: %w", err)
			}
			hasRecipients := false
			hasSecrets := false
			for _, tag := range existingTags {
				if app.IsUserRecipientTag(tag) {
					hasRecipients = true
				}
				if strings.HasPrefix(tag, "secrets-") {
					hasSecrets = true
				}
			}

			joinMode := hasRecipients || hasSecrets
			result.Mode = "initialize"
			result.HasSecrets = hasSecrets
			if joinMode {
				result.Mode = "join"
				humanPrintf(cmd, "Existing enbu setup detected for this repository.\n")
				humanPrintf(cmd, "Entering join mode — registering your key only.\n")
			}

			repoKey := app.RepoKeystoreKey(owner, repo)
			var publicKey string

			existingPriv, err := a.KeyStore.Load(app.KeystoreService, repoKey)
			if err == nil && len(existingPriv) > 0 {
				id, err := agecrypto.ParseX25519Identity(string(existingPriv))
				if err != nil {
					return fmt.Errorf("parsing existing private key: %w", err)
				}
				publicKey = id.Recipient().String()
				humanPrintf(cmd, "Using existing age public key: %s\n", publicKey)
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("loading private key from keystore: %w", err)
			} else {
				humanPrintf(cmd, "Generating new age key pair...\n")
				kp, err := age.GenerateKeyPair()
				if err != nil {
					return fmt.Errorf("generating age key pair: %w", err)
				}
				publicKey = kp.PublicKey
				result.KeyCreated = true
				humanPrintf(cmd, "Generated age public key: %s\n", publicKey)

				if err := a.KeyStore.Store(app.KeystoreService, repoKey, []byte(kp.Identity.String())); err != nil {
					return fmt.Errorf("storing private key: %w", err)
				}
			}
			result.PublicKey = publicKey

			ghClient := a.Platform
			if ghClient == nil {
				ghClient = gh.NewClient(accessToken)
			}

			fingerprint := age.Fingerprint(publicKey)
			tag := oci.CleanTag(fmt.Sprintf("%s-%s", username, fingerprint))
			ref := fmt.Sprintf("%s:%s%s", registryRef, app.RecipientTagPrefix(), tag)
			humanPrintf(cmd, "Pushing public key to registry...\n")
			pushOpts := &oci.PushOptions{
				SourceRepo: ghClient.SourceRepoURL(owner, repo),
			}
			if err := a.Registry.Push(ctx, ref, "application/vnd.enbu.recipient.age.v1", []byte(publicKey), accessToken, pushOpts); err != nil {
				return fmt.Errorf("pushing public key to GHCR: %w", err)
			}
			result.RecipientRegistered = true
			humanPrintf(cmd, "✓ Registered user public key.\n")

			if joinMode {
				humanPrintf(cmd, "\nYour key has been registered.\n")
				if hasSecrets {
					identities, err := app.LoadIdentitiesForRepo(a.KeyStore, owner, repo)
					if err != nil || len(identities) == 0 {
						result.NextSteps = append(result.NextSteps, "Ask an existing member to run 'enbu sync', then run 'enbu pull'.")
						humanPrintf(cmd, "Could not load decryption keys; run 'enbu pull' after an existing member runs 'enbu sync'.\n")
						updateGitignore()
						return finishInit(cmd, result, warnings)
					}
					env := projectCfg.CurrentEnvironment()
					secretsRef := fmt.Sprintf("%s:secrets-%s", registryRef, oci.CleanTag(env))
					ok, err := verifyCurrentUserCanDecrypt(ctx, a.Registry, secretsRef, accessToken, identities)
					if err != nil {
						warnings = append(warnings, fmt.Sprintf("failed to verify decryption: %v", err))
						humanErrorf(cmd, "Warning: failed to verify decryption: %v\n", err)
						humanPrintf(cmd, "Your key is registered, but we couldn't verify if you can decrypt the secrets.\n")
					} else if !ok {
						result.CanDecrypt = boolPointer(false)
						result.NextSteps = append(result.NextSteps, "Ask an existing member to run 'enbu sync', then run 'enbu pull'.")
						humanPrintf(cmd, "Your key is registered, but the existing secrets have not been re-encrypted for it yet.\n")
						humanPrintf(cmd, "Ask an existing member to run 'enbu sync', then run 'enbu pull'.\n")
					} else {
						result.CanDecrypt = boolPointer(true)
						result.NextSteps = append(result.NextSteps, "Run 'enbu pull' to access secrets.")
						humanPrintf(cmd, "✓ You can now run 'enbu pull' to access secrets.\n")
					}
				} else {
					result.NextSteps = append(result.NextSteps, "Wait for a member to run 'enbu add'.")
					humanPrintf(cmd, "No secrets exist yet. You can access them after a member runs 'enbu add'.\n")
				}
				updateGitignore()
				return finishInit(cmd, result, warnings)
			}

			if configMissing {
				if err := config.SaveProject(projectCfg); err != nil {
					return fmt.Errorf("creating enbu.toml: %w", err)
				}
				result.ConfigCreated = true
				humanPrintf(cmd, "✓ Created enbu.toml\n")
			}

			updateGitignore()

			if configMissing {
				if err := gitCommitInitFiles(ctx, gitClient(a), repoRoot); err != nil {
					result.CommitCreated = boolPointer(false)
					warnings = append(warnings, fmt.Sprintf("failed to commit init files: %v", err))
					result.NextSteps = append(result.NextSteps, "Run: git add enbu.toml .gitignore && git commit -m 'chore: add enbu config'")
					humanErrorf(cmd, "Warning: failed to commit init files: %v\n", err)
					humanPrintf(cmd, "  Run: git add enbu.toml .gitignore && git commit -m 'chore: add enbu config'\n")
				} else {
					result.CommitCreated = boolPointer(true)
					humanPrintf(cmd, "✓ Committed enbu.toml and .gitignore\n")
				}
			}

			humanPrintf(cmd, "\n🎉 enbu initialized!\n\n")
			humanPrintf(cmd, "Before sharing secrets, make the package at:\n")

			if ghClient.IsOrganization(ctx, owner) {
				result.PackageSettingsURL = fmt.Sprintf("https://github.com/orgs/%s/packages/container/%s-enbu/settings", owner, repo)
			} else {
				result.PackageSettingsURL = fmt.Sprintf("https://github.com/users/%s/packages/container/%s-enbu/settings", owner, repo)
			}
			result.NextSteps = append(result.NextSteps,
				"Set inherited access to the source repository.",
				"Push the commit with 'git push'.",
				"Run 'enbu switch -c dev' to create an environment.",
				"Run 'enbu add KEY VALUE' to add secrets.",
			)
			humanPrintf(cmd, "  %s\n\n", result.PackageSettingsURL)
			humanPrintf(cmd, "  1. Inherited access: set to \"Inherit access from source repository (recommended)\"\n\n")
			humanPrintf(cmd, "Then:\n")
			humanPrintf(cmd, "  2. Push the commit: git push\n")
			humanPrintf(cmd, "  3. Run 'enbu switch -c dev' to create an environment\n")
			humanPrintf(cmd, "  4. Run 'enbu add KEY VALUE' to add secrets\n")
			return finishInit(cmd, result, warnings)
		},
	}

	return cmd
}

type initResponse struct {
	Mode                string                 `json:"mode"`
	Repository          initRepositoryResponse `json:"repository"`
	Registry            string                 `json:"registry"`
	PublicKey           string                 `json:"public_key"`
	KeyCreated          bool                   `json:"key_created"`
	RecipientRegistered bool                   `json:"recipient_registered"`
	HasSecrets          bool                   `json:"has_secrets"`
	CanDecrypt          *bool                  `json:"can_decrypt"`
	ConfigCreated       bool                   `json:"config_created"`
	GitignoreUpdated    bool                   `json:"gitignore_updated"`
	CommitCreated       *bool                  `json:"commit_created"`
	PackageSettingsURL  string                 `json:"package_settings_url,omitempty"`
	NextSteps           []string               `json:"next_steps"`
}

type initRepositoryResponse struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func finishInit(cmd *cobra.Command, result initResponse, warnings []string) error {
	if jsonEnabled(cmd) {
		return writeJSON(cmd, result, warnings...)
	}
	return nil
}

func boolPointer(value bool) *bool {
	return &value
}

func registryHost(a *app.App) string {
	if a.RegistryHost != "" {
		return a.RegistryHost
	}
	return "ghcr.io"
}

func verifyCurrentUserCanDecrypt(ctx context.Context, reg app.Registry, secretsRef, token string, identities []*agecrypto.X25519Identity) (bool, error) {
	ciphertext, err := reg.Pull(ctx, secretsRef, token)
	if err != nil {
		return false, err
	}
	_, err = age.Decrypt(ciphertext, identities...)
	if err != nil {
		return false, nil
	}
	return true, nil
}

var gitignoreEntries = []string{
	".env",
	".env.*",
	"!.env.example",
}

func ensureProjectGitignore(repoRoot string, cfg *config.ProjectConfig) error {
	return ensureGitignore(repoRoot, projectGitignoreEntries(cfg)...)
}

func projectGitignoreEntries(cfg *config.ProjectConfig) []string {
	var entries []string
	for _, name := range cfg.EnvironmentNames() {
		env, err := cfg.Environment(name)
		if err != nil {
			continue
		}
		output := gitignorePatternForOutput(env.Output)
		if output != "" {
			entries = append(entries, output)
		}
	}
	return entries
}

func gitignorePatternForOutput(output string) string {
	output = strings.TrimSpace(output)
	if output == "" || filepath.IsAbs(output) {
		return ""
	}
	if strings.HasPrefix(output, "#") || strings.HasPrefix(output, "!") {
		return `\` + output
	}
	return output
}

func ensureGitignore(repoRoot string, extraEntries ...string) error {
	path := filepath.Join(repoRoot, ".gitignore")

	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}

	lines := strings.Split(existing, "\n")
	lineSet := make(map[string]bool)
	for _, l := range lines {
		lineSet[strings.TrimSpace(l)] = true
	}

	entries := append([]string{}, gitignoreEntries...)
	entries = append(entries, extraEntries...)

	var toAdd []string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !lineSet[entry] {
			toAdd = append(toAdd, entry)
			lineSet[entry] = true
		}
	}

	if len(toAdd) == 0 {
		return nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if existing != "" && !strings.HasSuffix(existing, "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}

	content := "\n# enbu - exclude .env files\n" + strings.Join(toAdd, "\n") + "\n"
	_, err = f.WriteString(content)
	return err
}

func gitCommitInitFiles(ctx context.Context, client gitprovider.Client, repoRoot string) error {
	return client.CommitFiles(
		ctx,
		repoRoot,
		[]string{"enbu.toml", ".gitignore"},
		"chore: add enbu config",
	)
}

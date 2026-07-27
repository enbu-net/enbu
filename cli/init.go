package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/config"
	gitprovider "github.com/enbu-net/enbu/provider/git"
	gh "github.com/enbu-net/enbu/provider/github"
	"github.com/enbu-net/enbu/utils/age"
	"github.com/enbu-net/enbu/utils/keystore"
	"github.com/enbu-net/enbu/utils/oci"
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

			projectCfg, err := config.LoadProject()
			configMissing := false
			if err != nil {
				if strings.Contains(err.Error(), "enbu.toml not found") {
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
			if joinMode {
				fmt.Println("Existing enbu setup detected for this repository.")
				fmt.Println("Entering join mode — registering your key only.")
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
				fmt.Printf("Using existing age public key: %s\n", publicKey)
			} else if err != nil && !errors.Is(err, keystore.ErrNotFound) {
				return fmt.Errorf("loading private key from keystore: %w", err)
			} else {
				fmt.Println("Generating new age key pair...")
				kp, err := age.GenerateKeyPair()
				if err != nil {
					return fmt.Errorf("generating age key pair: %w", err)
				}
				publicKey = kp.PublicKey
				fmt.Printf("Generated age public key: %s\n", publicKey)

				if err := a.KeyStore.Store(app.KeystoreService, repoKey, []byte(kp.Identity.String())); err != nil {
					return fmt.Errorf("storing private key: %w", err)
				}
			}

			ghClient := a.Platform
			if ghClient == nil {
				ghClient = gh.NewClient(accessToken)
			}

			fingerprint := age.Fingerprint(publicKey)
			tag := oci.CleanTag(fmt.Sprintf("%s-%s", username, fingerprint))
			ref := fmt.Sprintf("%s:%s%s", registryRef, app.RecipientTagPrefix(), tag)
			fmt.Println("Pushing public key to registry...")
			pushOpts := &oci.PushOptions{
				SourceRepo: ghClient.SourceRepoURL(owner, repo),
			}
			if err := a.Registry.Push(ctx, ref, "application/vnd.enbu.recipient.age.v1", []byte(publicKey), accessToken, pushOpts); err != nil {
				return fmt.Errorf("pushing public key to GHCR: %w", err)
			}
			fmt.Println("✓ Registered user public key.")

			if joinMode {
				fmt.Println("\nYour key has been registered.")
				if hasSecrets {
					identities, err := app.LoadIdentitiesForRepo(a.KeyStore, owner, repo)
					if err != nil || len(identities) == 0 {
						fmt.Println("Could not load decryption keys; run 'enbu pull' after an existing member runs 'enbu sync'.")
						return nil
					}
					env := projectCfg.CurrentEnvironment()
					secretsRef := fmt.Sprintf("%s:secrets-%s", registryRef, oci.CleanTag(env))
					ok, err := verifyCurrentUserCanDecrypt(ctx, a.Registry, secretsRef, accessToken, identities)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to verify decryption: %v\n", err)
						fmt.Println("Your key is registered, but we couldn't verify if you can decrypt the secrets.")
					} else if !ok {
						fmt.Println("Your key is registered, but the existing secrets have not been re-encrypted for it yet.")
						fmt.Println("Ask an existing member to run 'enbu sync', then run 'enbu pull'.")
					} else {
						fmt.Println("✓ You can now run 'enbu pull' to access secrets.")
					}
				} else {
					fmt.Println("No secrets exist yet. You can access them after a member runs 'enbu add'.")
				}
				ensureProjectGitignore(repoRoot, projectCfg)
				return nil
			}

			if configMissing {
				if err := config.SaveProject(projectCfg); err != nil {
					return fmt.Errorf("creating enbu.toml: %w", err)
				}
				fmt.Println("✓ Created enbu.toml")
			}

			ensureProjectGitignore(repoRoot, projectCfg)

			if configMissing {
				if err := gitCommitInitFiles(ctx, gitClient(a), repoRoot); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to commit init files: %v\n", err)
					fmt.Println("  Run: git add enbu.toml .gitignore && git commit -m 'chore: add enbu config'")
				} else {
					fmt.Println("✓ Committed enbu.toml and .gitignore")
				}
			}

			fmt.Println("\n🎉 enbu initialized!")
			fmt.Println("")
			fmt.Println("Before sharing secrets, make the package at:")

			if ghClient.IsOrganization(ctx, owner) {
				fmt.Printf("  https://github.com/orgs/%s/packages/container/%s-enbu/settings\n", owner, repo)
			} else {
				fmt.Printf("  https://github.com/users/%s/packages/container/%s-enbu/settings\n", owner, repo)
			}
			fmt.Println("")
			fmt.Println("  1. Inherited access: set to \"Inherit access from source repository (recommended)\"")
			fmt.Println("")
			fmt.Println("Then:")
			fmt.Println("  2. Push the commit: git push")
			fmt.Println("  3. Run 'enbu switch -c dev' to create an environment")
			fmt.Println("  4. Run 'enbu add KEY VALUE' to add secrets")
			return nil
		},
	}

	return cmd
}

func registryHost(a *app.App) string {
	if a.RegistryHost != "" {
		return a.RegistryHost
	}
	return "ghcr.io"
}

func verifyCurrentUserCanDecrypt(ctx context.Context, reg app.Registry, secretsRef, token string, identities []agecrypto.Identity) (bool, error) {
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
	".enbu.local",
}

func ensureProjectGitignore(repoRoot string, cfg *config.ProjectConfig) {
	if err := ensureGitignore(repoRoot, projectGitignoreEntries(cfg)...); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to update .gitignore: %v\n", err)
	} else {
		fmt.Println("✓ Updated .gitignore")
	}
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

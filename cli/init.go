package cli

import (
	"fmt"
	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
)

func newInitCommand(a *app.App) *cobra.Command {
	var settings config.StorageConfig
	cmd := &cobra.Command{Use: "init", Short: "Initialize or join a workspace", Args: appArgs(cobra.NoArgs), RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.LoadProjectFrom(a.RepositoryDir)
		if err == nil {
			settings = cfg.Storage
		}
		if cmd.Flags().Changed("region") {
			settings.Region, _ = cmd.Flags().GetString("region")
		}
		if cmd.Flags().Changed("endpoint") {
			settings.Endpoint, _ = cmd.Flags().GetString("endpoint")
		}
		if cmd.Flags().Changed("path-style") {
			settings.PathStyle, _ = cmd.Flags().GetBool("path-style")
		}
		if cmd.Flags().Changed("oci-auth") {
			settings.OCIAuth, _ = cmd.Flags().GetString("oci-auth")
		}
		if cmd.Flags().Changed("plain-http") {
			settings.PlainHTTP, _ = cmd.Flags().GetBool("plain-http")
		}
		if a.StorageURL != "" {
			settings.URL = a.StorageURL
		}
		a.InitStorage = &settings
		defer func() { a.InitStorage = nil }()
		result, err := a.InitializeRepository(cmd.Context())
		if err != nil {
			return err
		}
		if a.RepositoryDir != "" {
			if err := ensureProjectGitignore(a.RepositoryDir, cfgOrDefault(cfg)); err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("failed to update .gitignore: %v", err))
			}
		} else if err := ensureProjectGitignore(".", cfgOrDefault(cfg)); err != nil {
			result.Warnings = append(result.Warnings, err.Error())
		}
		if jsonEnabled(cmd) {
			return writeJSON(cmd, result, result.Warnings...)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Workspace: %s\nStorage: %s\nRecipient: %s\n", result.WorkspaceID, result.Storage, result.PublicKey)
		for _, warning := range result.Warnings {
			cmd.PrintErrln(warning)
		}
		if result.Pending {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Waiting for approval. Ask an admin to run 'enbu member approve' and confirm this fingerprint:\n  %s\n", result.Fingerprint)
		} else if result.CanDecrypt != nil && !*result.CanDecrypt {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Ask an existing member to run 'enbu sync', then run 'enbu pull'.")
		}
		return nil
	}}
	cmd.Flags().StringVar(&settings.Region, "region", "", "S3 region")
	cmd.Flags().StringVar(&settings.Endpoint, "endpoint", "", "S3 service endpoint")
	cmd.Flags().BoolVar(&settings.PathStyle, "path-style", false, "Use S3 path-style addressing")
	cmd.Flags().StringVar(&settings.OCIAuth, "oci-auth", "docker", "OCI credentials: docker or github")
	cmd.Flags().BoolVar(&settings.PlainHTTP, "plain-http", false, "Use HTTP for a local OCI registry")
	return cmd
}
func cfgOrDefault(cfg *config.ProjectConfig) *config.ProjectConfig {
	if cfg != nil {
		return cfg
	}
	return config.NewProjectWithEnvironment(app.DefaultEnvironment)
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

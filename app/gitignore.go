package app

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/config"
)

// baseGitignoreEntries keep every dotenv file but the example out of Git.
var baseGitignoreEntries = []string{
	".env",
	".env.*",
	"!.env.example",
}

// gitignoreEntries are the patterns that keep the files a pull writes for
// cfg's environments out of Git.
func gitignoreEntries(cfg *config.ProjectConfig) []string {
	entries := append([]string{}, baseGitignoreEntries...)
	for _, name := range cfg.EnvironmentNames() {
		env, err := cfg.Environment(name)
		if err != nil {
			continue
		}
		output := strings.TrimSpace(env.Output)
		if output == "" || filepath.IsAbs(output) {
			continue
		}
		entries = append(entries, gitignoreLiteral(filepath.ToSlash(output)))
	}
	return entries
}

// gitignoreLiteral returns a .gitignore pattern that matches path only: glob
// characters and a leading # or ! are escaped. Outputs are trimmed, so no
// trailing space needs escaping.
func gitignoreLiteral(path string) string {
	var b strings.Builder
	for _, r := range path {
		if strings.ContainsRune(`\*?[`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	out := b.String()
	if strings.HasPrefix(out, "#") || strings.HasPrefix(out, "!") {
		out = `\` + out
	}
	return out
}

// ensureGitignore appends to the repository's .gitignore the entries of cfg it
// does not list yet.
func (a *App) ensureGitignore(cfg *config.ProjectConfig) error {
	path := filepath.Join(a.RepositoryDir, ".gitignore")
	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}
	listed := make(map[string]bool)
	for _, line := range strings.Split(existing, "\n") {
		listed[strings.TrimSpace(line)] = true
	}
	var toAdd []string
	for _, entry := range gitignoreEntries(cfg) {
		entry = strings.TrimSpace(entry)
		if entry != "" && !listed[entry] {
			toAdd = append(toAdd, entry)
			listed[entry] = true
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
	_, err = f.WriteString("\n# enbu - exclude .env files\n" + strings.Join(toAdd, "\n") + "\n")
	return err
}

package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/fsutil"
)

// baseGitignoreEntries keep every dotenv file but the example out of Git.
var baseGitignoreEntries = []string{
	"/" + config.ProjectLockName,
	".env",
	".env.*",
	"!.env.example",
}

// gitignoreEntries are the patterns that keep the files a pull writes for
// cfg's environments out of Git.
func gitignoreEntries(cfg *config.ProjectConfig) []string {
	var entries []string
	for _, name := range cfg.EnvironmentNames() {
		env, err := cfg.Environment(name)
		if err != nil {
			continue
		}
		output := strings.TrimSpace(env.Output)
		// A leading slash is rooted on Windows too, where filepath.IsAbs
		// needs a drive letter.
		if output == "" || strings.HasPrefix(output, "/") || filepath.IsAbs(output) {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(output))
		entries = append(entries, "/"+gitignoreLiteral(clean))
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

// ensureGitignore puts missing defaults before existing rules and adds exact
// output exclusions after them. Defaults must never unignore an old output.
func (a *App) ensureGitignore(cfg *config.ProjectConfig) error {
	path := filepath.Join(a.RepositoryDir, ".gitignore")
	perm := os.FileMode(0o644)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New(".gitignore must be a regular file")
		}
		perm = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	existing, bom := strings.CutPrefix(string(data), "\uFEFF")
	listed := make(map[string]bool)
	for _, line := range strings.Split(existing, "\n") {
		listed[strings.TrimSuffix(line, "\r")] = true
	}
	var defaults []string
	for _, rule := range baseGitignoreEntries {
		if !listed[rule] {
			defaults = append(defaults, rule)
		}
	}
	content := existing
	if len(defaults) > 0 {
		content = "# enbu - dotenv defaults\n" + strings.Join(defaults, "\n") + "\n" + existing
	}

	clear(listed)
	for _, line := range strings.Split(content, "\n") {
		rule := strings.TrimSuffix(line, "\r")
		if rule == "!.env.example" {
			for path := range listed {
				if filepath.Base(path) == ".env.example" {
					delete(listed, path)
				}
			}
		} else if strings.HasPrefix(rule, "!") {
			clear(listed)
		}
		listed[rule] = true
	}
	var outputs []string
	for _, rule := range gitignoreEntries(cfg) {
		if !listed[rule] && (rule != "/.env" || !listed[".env"]) {
			outputs = append(outputs, rule)
			listed[rule] = true
		}
	}
	if len(outputs) > 0 {
		content = strings.TrimSuffix(content, "\n") + "\n\n# enbu - secret outputs\n" + strings.Join(outputs, "\n") + "\n"
	}
	if content == existing {
		return nil
	}
	if bom {
		content = "\uFEFF" + content
	}
	return fsutil.WriteFileAtomic(path, []byte(content), perm)
}

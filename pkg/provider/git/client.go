// Package git finds the Git repository a folder belongs to and its origin
// remote by reading the repository's files. It never runs the git command:
// the person may have Git only inside GitHub Desktop or an editor, and an
// app started from the desktop may not see the git their terminal runs.
package git

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/pkg/fsutil"
)

type Repository struct {
	Root      string
	OriginURL string
	HasGit    bool
	HasRemote bool
}

type Client interface {
	Inspect(ctx context.Context, path string) (Repository, error)
}

// FileClient reads a repository's .git directory, or the .git file of a
// worktree or submodule, and its config.
type FileClient struct{}

func NewClient() FileClient {
	return FileClient{}
}

// Inspect finds the nearest folder at or above path that holds .git, as git
// does. A folder outside any repository is not an error: HasGit is false.
func (FileClient) Inspect(ctx context.Context, path string) (Repository, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Repository{}, fmt.Errorf("resolving repository path: %w", err)
	}
	repository := Repository{Root: fsutil.Canonical(abs)}
	for dir := abs; ; dir = filepath.Dir(dir) {
		if err := ctx.Err(); err != nil {
			return Repository{}, err
		}
		gitDir, found, err := findGitDir(dir)
		if err != nil {
			return Repository{}, err
		}
		if found {
			repository.Root = fsutil.Canonical(dir)
			repository.HasGit = true
			url := originURL(gitDir)
			repository.OriginURL = url
			repository.HasRemote = url != ""
			return repository, nil
		}
		if filepath.Dir(dir) == dir {
			return repository, nil
		}
	}
}

// findGitDir reports the Git directory of dir: dir/.git itself, or the one a
// .git file names with "gitdir: ".
func findGitDir(dir string) (string, bool, error) {
	dotGit := filepath.Join(dir, ".git")
	info, err := os.Stat(dotGit)
	if err != nil {
		// Missing, or a folder this user may not read: no repository here.
		return "", false, nil
	}
	if info.IsDir() {
		return dotGit, isGitDir(dotGit), nil
	}
	data, err := os.ReadFile(dotGit)
	if err != nil {
		return "", false, nil
	}
	line, _, _ := strings.Cut(string(data), "\n")
	target, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "gitdir: ")
	if !ok || target == "" {
		return "", false, nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	return target, isGitDir(target), nil
}

// isGitDir tells a Git directory from a folder that is only named .git: git
// writes HEAD into every one, a freshly initialized repository included.
func isGitDir(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, "HEAD"))
	return err == nil && !info.IsDir()
}

// originURL reads remote.origin.url from the repository's config, which a
// worktree shares with its main repository through commondir. A config that
// cannot be read leaves the repository without a remote, not undetected.
func originURL(gitDir string) string {
	common := gitDir
	if data, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		target := strings.TrimRight(string(data), "\r\n")
		if !filepath.IsAbs(target) {
			target = filepath.Join(gitDir, target)
		}
		common = target
	}
	data, err := os.ReadFile(filepath.Join(common, "config"))
	if err != nil {
		return ""
	}
	return configValue(data, "remote", "origin", "url")
}

// configValue returns the last value of section.subsection.key in a git
// config file, as git does for a key given more than once. Section and key
// names ignore case; subsection names do not.
func configValue(data []byte, section, subsection, key string) string {
	var value string
	inSection := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			name, sub, rest := parseHeader(line)
			inSection = strings.EqualFold(name, section) && sub == subsection
			line = strings.TrimSpace(rest)
			if line == "" {
				continue
			}
		}
		if !inSection || line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		name, raw, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), key) {
			continue
		}
		value = unquote(raw)
	}
	return value
}

// parseHeader splits `[remote "origin"]` into its section and subsection,
// and returns what follows the header on the same line.
func parseHeader(line string) (section, subsection, rest string) {
	end := strings.LastIndex(line, "]")
	if end < 0 {
		return "", "", ""
	}
	header, rest := line[1:end], line[end+1:]
	name, quoted, ok := strings.Cut(header, " ")
	if !ok {
		// The old [section.subsection] spelling.
		name, sub, _ := strings.Cut(header, ".")
		return name, sub, rest
	}
	quoted = strings.TrimSpace(quoted)
	quoted = strings.TrimSuffix(strings.TrimPrefix(quoted, `"`), `"`)
	quoted = strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(quoted)
	return name, quoted, rest
}

// unquote reads a config value: it drops a trailing comment and the quotes
// around parts of it, and keeps the escaped characters git allows.
func unquote(raw string) string {
	var b strings.Builder
	quoted := false
	raw = strings.TrimSpace(raw)
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '"':
			quoted = !quoted
		case c == '\\' && i+1 < len(raw):
			i++
			switch raw[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(raw[i])
			}
		case !quoted && (c == '#' || c == ';'):
			return strings.TrimSpace(b.String())
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

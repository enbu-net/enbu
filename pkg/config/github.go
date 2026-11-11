package config

import (
	"errors"
	"net/url"
	"strings"
)

// ParseGitHubRemote returns the owner and repository of a github.com remote
// (git@github.com:owner/repo, https://github.com/owner/repo or
// ssh://git@github.com/owner/repo, each with or without .git). Other hosts are
// an error.
func ParseGitHubRemote(remote string) (string, string, error) {
	var path string
	if rest, ok := strings.CutPrefix(remote, "git@github.com:"); ok {
		path = rest
	} else {
		u, err := url.Parse(remote)
		if err != nil || (u.Scheme != "https" && u.Scheme != "ssh") || u.Hostname() != "github.com" {
			return "", "", errors.New("not a GitHub remote")
		}
		path = u.Path
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	owner, repo, ok := strings.Cut(path, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", errors.New("not a GitHub remote")
	}
	return owner, repo, nil
}

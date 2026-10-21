package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// TagDeleter removes the registry version that a tag names. A registry has no
// delete API for tags on its own, so a provider supplies one.
type TagDeleter interface {
	DeleteTag(ctx context.Context, tag string) error
}

// OCIOption configures an OCI store.
type OCIOption func(*ociStore)

// WithTagDeleter lets the store delete revisions, which plain OCI cannot.
func WithTagDeleter(d TagDeleter) OCIOption { return func(s *ociStore) { s.deleter = d } }

// GHCRPackages deletes package versions of ghcr.io through the GitHub Packages
// API. The token needs read:packages and delete:packages.
type GHCRPackages struct {
	// Token returns the credential for the API, so it is read when needed.
	Token func() (string, error)
	// Owner and Package come from ghcr.io/<owner>/<package>.
	Owner, Package string
	// BaseURL is the API root; empty means https://api.github.com.
	BaseURL string
	Client  *http.Client
}

// GHCRPackagesFor builds a deleter for a repository reference such as
// ghcr.io/owner/repo-enbu. It reports false for other registries.
func GHCRPackagesFor(ref string, token func() (string, error)) (*GHCRPackages, bool) {
	host, path, ok := strings.Cut(ref, "/")
	if !ok || host != "ghcr.io" {
		return nil, false
	}
	owner, pkg, ok := strings.Cut(path, "/")
	if !ok || owner == "" || pkg == "" {
		return nil, false
	}
	return &GHCRPackages{Token: token, Owner: owner, Package: pkg}, true
}

func (g *GHCRPackages) base() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/")
	}
	return "https://api.github.com"
}

func (g *GHCRPackages) do(ctx context.Context, method, path string, out any) (int, error) {
	token, err := g.Token()
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, g.base()+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	client := g.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("GitHub Packages API %s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (g *GHCRPackages) packagePath(ctx context.Context) (string, error) {
	var owner struct {
		Type string `json:"type"`
	}
	if _, err := g.do(ctx, http.MethodGet, "/users/"+url.PathEscape(g.Owner), &owner); err != nil {
		return "", err
	}
	scope := "users/"
	if owner.Type == "Organization" {
		scope = "orgs/"
	}
	return "/" + scope + url.PathEscape(g.Owner) + "/packages/container/" + url.PathEscape(g.Package), nil
}

// DeleteTag deletes the package version that carries tag. A version deletes
// every tag it carries, so a version with any other tag is left alone.
func (g *GHCRPackages) DeleteTag(ctx context.Context, tag string) error {
	pkg, err := g.packagePath(ctx)
	if err != nil {
		return err
	}
	for page := 1; ; page++ {
		var versions []struct {
			ID       int64 `json:"id"`
			Metadata struct {
				Container struct {
					Tags []string `json:"tags"`
				} `json:"container"`
			} `json:"metadata"`
		}
		if _, err := g.do(ctx, http.MethodGet, fmt.Sprintf("%s/versions?per_page=100&page=%d", pkg, page), &versions); err != nil {
			return err
		}
		for _, v := range versions {
			tags := v.Metadata.Container.Tags
			if len(tags) == 0 || !contains(tags, tag) {
				continue
			}
			if len(tags) > 1 {
				return fmt.Errorf("refusing to delete %s: its package version also carries %s", tag, strings.Join(without(tags, tag), ", "))
			}
			_, err := g.do(ctx, http.MethodDelete, fmt.Sprintf("%s/versions/%d", pkg, v.ID), nil)
			return err
		}
		if len(versions) < 100 {
			return fmt.Errorf("%w: no package version carries %s", ErrNotFound, tag)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func without(ss []string, s string) []string {
	var out []string
	for _, x := range ss {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

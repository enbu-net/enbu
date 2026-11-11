package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Repository is where the desktop app is released.
const Repository = "enbu-net/enbu"

// latestURL is GitHub's newest published, non-prerelease release.
var latestURL = "https://api.github.com/repos/" + Repository + "/releases/latest"

// Release is a published release and the files the updater needs from it.
type Release struct {
	Version string
	URL     string            // the release page
	Assets  map[string]string // file name -> download URL
}

// Latest asks GitHub for the newest release. It needs no sign-in: the
// repository is public, and the signature, not GitHub, is what the updater trusts.
func Latest(ctx context.Context, client *http.Client) (Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("%w: fetch the latest release: %w", ErrDownload, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("%w: fetch the latest release: %s", ErrDownload, resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return Release{}, fmt.Errorf("read the latest release: %w", err)
	}
	if !IsRelease(body.TagName) {
		return Release{}, fmt.Errorf("latest release has no version: %q", body.TagName)
	}
	release := Release{Version: body.TagName, URL: body.HTMLURL, Assets: make(map[string]string, len(body.Assets))}
	for _, asset := range body.Assets {
		release.Assets[asset.Name] = asset.URL
	}
	return release, nil
}

// AssetName is the desktop archive a release builds for one platform; the
// names come from .github/workflows/release-build.yaml.
func AssetName(version, goos, goarch string) (string, bool) {
	var ext string
	switch goos {
	case "linux":
		ext = "tar.gz"
	case "darwin":
		ext = "dmg"
	case "windows":
		ext = "zip"
	default:
		return "", false
	}
	switch goarch {
	case "amd64", "arm64":
	default:
		return "", false
	}
	return fmt.Sprintf("enbu-desktop_%s_%s_%s.%s", version, goos, goarch, ext), true
}

const (
	checksumsName = "checksums.txt"
	bundleSuffix  = ".sigstore.json"
)

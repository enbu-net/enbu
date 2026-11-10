package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// maxDownloadSize bounds one release file.
const maxDownloadSize = 256 << 20

// Status is what a check found.
type Status struct {
	Method  Method `json:"method"`
	Current string `json:"current"`
	// Latest is empty when the method does not look for releases
	// (development builds and editor extensions).
	Latest string `json:"latest,omitempty"`
	// Available is true when Latest is newer than Current.
	Available bool   `json:"available"`
	URL       string `json:"url,omitempty"`
}

// Updater checks for and installs releases of one installation.
type Updater struct {
	Client  *http.Client
	Method  Method
	Version string
	GOOS    string
	GOARCH  string
	// Target is what Install replaces (see Target).
	Target string
	// CacheDir keeps the Sigstore trusted root and the downloads.
	CacheDir string
	// TrustedRoot returns the Sigstore trusted root; nil fetches it over
	// TUF (the root of trust embedded in sigstore-go), cached in CacheDir.
	TrustedRoot func(ctx context.Context) (root.TrustedMaterial, error)
	// Clock bounds the release lookup; nil uses the real clock.
	Clock clock.Clock
	// latest and verify are replaceable in tests.
	latest func(ctx context.Context, client *http.Client) (Release, error)
	verify func(trusted root.TrustedMaterial, checksums, bundleJSON []byte) error
}

func (u *Updater) client() *http.Client {
	if u.Client != nil {
		return u.Client
	}
	return http.DefaultClient
}

// Looks reports whether a method looks for releases at all: editor
// extensions are updated by the editor, and development builds have no
// release to compare with.
func (m Method) Looks() bool {
	return m != MethodEditor && m != MethodDevelopment
}

// Check compares the installation with the newest release.
func (u *Updater) Check(ctx context.Context) (Status, error) {
	status, _, err := u.check(ctx)
	return status, err
}

func (u *Updater) check(ctx context.Context) (Status, Release, error) {
	status := Status{Method: u.Method, Current: u.Version}
	if !u.Method.Looks() {
		return status, Release{}, nil
	}
	latest := u.latest
	if latest == nil {
		latest = Latest
	}
	// The client's timeout fits a whole archive; the release lookup should
	// not keep the settings screen waiting that long.
	c := u.Clock
	if c == nil {
		c = clock.New()
	}
	lookup, cancel := clock.WithTimeout(ctx, c, lookupTimeout)
	defer cancel()
	release, err := latest(lookup, u.client())
	if err != nil {
		return status, Release{}, err
	}
	status.Latest = release.Version
	status.URL = release.URL
	status.Available = Newer(u.Version, release.Version)
	return status, release, nil
}

// lookupTimeout bounds the request for the newest release.
const lookupTimeout = 30 * time.Second

// ErrDownload marks a failure to reach GitHub or to download a release
// file; trying again later may work.
var ErrDownload = errors.New("download failed")

// ErrNotSelfManaged means the installation is updated some other way.
var ErrNotSelfManaged = errors.New("this installation is not updated by the app")

// Update installs the newest release when it is newer: it downloads
// checksums.txt and its Sigstore bundle, verifies them, downloads this
// platform's archive, checks it against checksums.txt and only then
// replaces the app. It returns the status after the update.
func (u *Updater) Update(ctx context.Context) (Status, error) {
	if u.Method != MethodSelf {
		return Status{Method: u.Method, Current: u.Version}, ErrNotSelfManaged
	}
	status, release, err := u.check(ctx)
	if err != nil || !status.Available {
		return status, err
	}
	asset, ok := AssetName(release.Version, u.GOOS, u.GOARCH)
	if !ok {
		return status, fmt.Errorf("no release archive for %s/%s", u.GOOS, u.GOARCH)
	}
	assetURL, checksumsURL, bundleURL := release.Assets[asset], release.Assets[checksumsName], release.Assets[checksumsName+bundleSuffix]
	if assetURL == "" || checksumsURL == "" || bundleURL == "" {
		return status, fmt.Errorf("%w: release %s lacks %s, %s or its signature", ErrUnverified, release.Version, asset, checksumsName)
	}

	checksums, err := u.fetch(ctx, checksumsURL, 1<<20)
	if err != nil {
		return status, err
	}
	bundleJSON, err := u.fetch(ctx, bundleURL, 1<<20)
	if err != nil {
		return status, err
	}
	trusted, err := u.trustedRoot(ctx)
	if err != nil {
		return status, fmt.Errorf("load the Sigstore trusted root: %w", err)
	}
	verify := u.verify
	if verify == nil {
		verify = VerifyChecksums
	}
	if err := verify(trusted, checksums, bundleJSON); err != nil {
		return status, err
	}
	want, err := ChecksumFor(checksums, asset)
	if err != nil {
		return status, err
	}

	downloads, err := privateDir(u.CacheDir, "downloads")
	if err != nil {
		return status, err
	}
	archive, err := os.CreateTemp(downloads, "update-*-"+asset)
	if err != nil {
		return status, err
	}
	defer func() {
		_ = archive.Close()
		_ = os.Remove(archive.Name())
	}()
	if err := u.download(ctx, assetURL, archive); err != nil {
		return status, err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return status, err
	}
	if err := VerifyFile(archive, want); err != nil {
		return status, err
	}
	if err := Install(ctx, u.GOOS, archive, u.Target); err != nil {
		return status, fmt.Errorf("install %s: %w", release.Version, err)
	}
	return Status{Method: u.Method, Current: release.Version, Latest: release.Version, URL: release.URL}, nil
}

// privateDir creates dir/name for this user alone and refuses one that
// others may write to: what is downloaded there is verified and installed,
// so nobody else may swap it in between. CacheDir must be set; there is no
// fallback to a shared temporary directory.
func privateDir(cacheDir, name string) (string, error) {
	if cacheDir == "" {
		return "", errors.New("no cache directory for updates")
	}
	dir := filepath.Join(cacheDir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || !ownedPrivately(info) {
		return "", fmt.Errorf("%s is not a private directory of this user", dir)
	}
	return dir, nil
}

func (u *Updater) trustedRoot(ctx context.Context) (root.TrustedMaterial, error) {
	if u.TrustedRoot != nil {
		return u.TrustedRoot(ctx)
	}
	cache, err := privateDir(u.CacheDir, "sigstore")
	if err != nil {
		return nil, err
	}
	opts := tuf.DefaultOptions().WithContext(ctx).WithCachePath(cache)
	return root.FetchTrustedRootWithOptions(opts)
}

func (u *Updater) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDownload, url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: %s: %s", ErrDownload, url, resp.Status)
	}
	return resp, nil
}

func (u *Updater) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	resp, err := u.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrDownload, url, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("download %s: too large", url)
	}
	return data, nil
}

func (u *Updater) download(ctx context.Context, url string, w io.Writer) error {
	resp, err := u.get(ctx, url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return copyBody(w, resp.Body, url)
}

// copyBody copies a release file. Only a failed read is a download failure;
// a failed local write is not.
func copyBody(w io.Writer, body io.Reader, url string) error {
	n, err := io.Copy(w, io.LimitReader(bodyReader{body}, maxDownloadSize+1))
	var read readError
	if errors.As(err, &read) {
		return fmt.Errorf("%w: %s: %w", ErrDownload, url, read.err)
	}
	if err != nil {
		return err
	}
	if n > maxDownloadSize {
		return fmt.Errorf("download %s: too large", url)
	}
	return nil
}

// bodyReader marks the errors of failed reads, so that io.Copy's result
// tells them apart from failed writes.
type bodyReader struct{ r io.Reader }

func (b bodyReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && err != io.EOF {
		err = readError{err}
	}
	return n, err
}

type readError struct{ err error }

func (e readError) Error() string { return e.err.Error() }
func (e readError) Unwrap() error { return e.err }

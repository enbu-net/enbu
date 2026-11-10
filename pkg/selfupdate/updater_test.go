package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// releaseServer serves a release whose archive holds a new Linux binary.
func releaseServer(t *testing.T, version string, tamper bool) (*httptest.Server, func(context.Context, *http.Client) (Release, error)) {
	t.Helper()
	dir := t.TempDir()
	asset, _ := AssetName(version, "linux", "amd64")
	archive := filepath.Join(dir, asset)
	writeTarGz(t, archive, map[string]string{"./enbu-desktop": "new " + version})
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if tamper {
		data = append(data, 0)
	}
	checksums := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), asset)
	mux := http.NewServeMux()
	mux.HandleFunc("/"+asset, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) })
	mux.HandleFunc("/checksums.txt", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(checksums)) })
	mux.HandleFunc("/checksums.txt.sigstore.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	latest := func(context.Context, *http.Client) (Release, error) {
		return Release{
			Version: version,
			URL:     srv.URL + "/release",
			Assets: map[string]string{
				asset:                         srv.URL + "/" + asset,
				"checksums.txt":               srv.URL + "/checksums.txt",
				"checksums.txt.sigstore.json": srv.URL + "/checksums.txt.sigstore.json",
			},
		}, nil
	}
	return srv, latest
}

func testUpdater(t *testing.T, latest func(context.Context, *http.Client) (Release, error), verifyErr error) (*Updater, string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "enbu-desktop")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Updater{
		Method:   MethodSelf,
		Version:  "v0.9.0",
		GOOS:     "linux",
		GOARCH:   "amd64",
		Target:   target,
		CacheDir: filepath.Join(dir, "cache"),
		TrustedRoot: func(context.Context) (root.TrustedMaterial, error) {
			return &root.TrustedRoot{}, nil
		},
		latest: latest,
		verify: func(root.TrustedMaterial, []byte, []byte) error { return verifyErr },
	}, target
}

func TestUpdateInstallsANewerVerifiedRelease(t *testing.T) {
	_, latest := releaseServer(t, "v0.10.0", false)
	u, target := testUpdater(t, latest, nil)

	status, err := u.Update(context.Background())
	if err != nil {
		t.Fatalf("Update() = %v", err)
	}
	if status.Current != "v0.10.0" || status.Available {
		t.Errorf("status = %+v", status)
	}
	if got := readFile(t, target); got != "new v0.10.0" {
		t.Errorf("target = %q", got)
	}
	entries, _ := os.ReadDir(filepath.Join(u.CacheDir, "downloads"))
	if len(entries) != 0 {
		t.Errorf("downloads left behind: %v", entries)
	}
}

func TestUpdateRefusesAnUnverifiedSignature(t *testing.T) {
	_, latest := releaseServer(t, "v0.10.0", false)
	u, target := testUpdater(t, latest, fmt.Errorf("%w: bad signature", ErrUnverified))

	if _, err := u.Update(context.Background()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Update() = %v, want ErrUnverified", err)
	}
	if got := readFile(t, target); got != "old" {
		t.Errorf("target = %q, want old", got)
	}
}

func TestUpdateRefusesAnArchiveThatDoesNotMatchItsChecksum(t *testing.T) {
	_, latest := releaseServer(t, "v0.10.0", true)
	u, target := testUpdater(t, latest, nil)

	if _, err := u.Update(context.Background()); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Update() = %v, want ErrUnverified", err)
	}
	if got := readFile(t, target); got != "old" {
		t.Errorf("target = %q, want old", got)
	}
}

func TestUpdateDoesNothingWithoutANewerRelease(t *testing.T) {
	_, latest := releaseServer(t, "v0.9.0", false)
	u, target := testUpdater(t, latest, nil)
	u.verify = func(root.TrustedMaterial, []byte, []byte) error {
		t.Error("nothing should be verified without a newer release")
		return nil
	}

	status, err := u.Update(context.Background())
	if err != nil || status.Available {
		t.Fatalf("Update() = %+v, %v", status, err)
	}
	if got := readFile(t, target); got != "old" {
		t.Errorf("target = %q, want old", got)
	}
}

func TestUpdateRefusesInstallationsItDoesNotManage(t *testing.T) {
	for _, method := range []Method{MethodHomebrew, MethodSystemPackage, MethodEditor, MethodDevelopment, MethodManual} {
		u := &Updater{Method: method, Version: "v0.9.0"}
		if _, err := u.Update(context.Background()); !errors.Is(err, ErrNotSelfManaged) {
			t.Errorf("Update(%s) = %v, want ErrNotSelfManaged", method, err)
		}
	}
}

func TestCheck(t *testing.T) {
	_, latest := releaseServer(t, "v0.10.0", false)
	u, _ := testUpdater(t, latest, nil)
	u.Method = MethodHomebrew
	status, err := u.Check(context.Background())
	if err != nil || !status.Available || status.Latest != "v0.10.0" || status.Method != MethodHomebrew {
		t.Errorf("Check() = %+v, %v", status, err)
	}

	u.Method = MethodEditor
	u.latest = func(context.Context, *http.Client) (Release, error) {
		t.Error("an editor extension should not look for releases")
		return Release{}, nil
	}
	if status, err := u.Check(context.Background()); err != nil || status.Latest != "" {
		t.Errorf("Check(editor) = %+v, %v", status, err)
	}
}

func TestLatestReadsTheGitHubRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		_, _ = w.Write([]byte(`{"tag_name":"v0.10.0","html_url":"https://github.com/enbu-net/enbu/releases/tag/v0.10.0","assets":[{"name":"checksums.txt","browser_download_url":"https://example.invalid/checksums.txt"}]}`))
	}))
	defer srv.Close()
	old := latestURL
	latestURL = srv.URL
	defer func() { latestURL = old }()

	release, err := Latest(context.Background(), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "v0.10.0" || release.Assets["checksums.txt"] == "" {
		t.Errorf("release = %+v", release)
	}
}

func TestLatestReportsDownloadFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer srv.Close()
	old := latestURL
	latestURL = srv.URL
	defer func() { latestURL = old }()

	if _, err := Latest(context.Background(), srv.Client()); !errors.Is(err, ErrDownload) {
		t.Errorf("Latest() = %v, want ErrDownload", err)
	}
}

func TestUpdateNeedsAPrivateCacheDirectory(t *testing.T) {
	_, latest := releaseServer(t, "v0.10.0", false)
	u, target := testUpdater(t, latest, nil)
	u.CacheDir = ""
	if _, err := u.Update(context.Background()); err == nil {
		t.Fatal("Update() without a cache directory = nil")
	}

	shared := t.TempDir()
	if err := os.Mkdir(filepath.Join(shared, "downloads"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(shared, "downloads"), 0o777); err != nil {
		t.Fatal(err)
	}
	u.CacheDir = shared
	if _, err := u.Update(context.Background()); err == nil && runtime.GOOS != "windows" {
		t.Fatal("Update() into a world-writable directory = nil")
	}
	if got := readFile(t, target); got != "old" && runtime.GOOS != "windows" {
		t.Errorf("target = %q, want old", got)
	}
}

func shortBodyServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Promise more than is sent, so the read fails partway.
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("partial"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestBodyReadFailuresAreDownloadFailures(t *testing.T) {
	srv := shortBodyServer(t)
	u := &Updater{Client: srv.Client()}
	if _, err := u.fetch(context.Background(), srv.URL, 1024); !errors.Is(err, ErrDownload) {
		t.Errorf("fetch() = %v, want ErrDownload", err)
	}
	var buf bytes.Buffer
	if err := u.download(context.Background(), srv.URL, &buf); !errors.Is(err, ErrDownload) {
		t.Errorf("download() = %v, want ErrDownload", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestLocalWriteFailuresAreNotDownloadFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("archive"))
	}))
	t.Cleanup(srv.Close)
	u := &Updater{Client: srv.Client()}
	err := u.download(context.Background(), srv.URL, failingWriter{})
	if err == nil || errors.Is(err, ErrDownload) {
		t.Errorf("download() = %v, want a non-download error", err)
	}
}

func TestCheckBoundsTheReleaseLookup(t *testing.T) {
	var deadline time.Time
	u := &Updater{
		Method:  MethodSelf,
		Version: "v0.9.0",
		latest: func(ctx context.Context, _ *http.Client) (Release, error) {
			deadline, _ = ctx.Deadline()
			return Release{Version: "v0.9.0"}, nil
		},
	}
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if deadline.IsZero() || time.Until(deadline) > lookupTimeout {
		t.Errorf("lookup deadline = %v, want within %v", deadline, lookupTimeout)
	}
}

// dataAndError returns its data and a read error from the same Read.
type dataAndError struct{ err error }

func (r dataAndError) Read(p []byte) (int, error) {
	return copy(p, "partial"), r.err
}

func TestAFailedWriteWinsOverAFailedRead(t *testing.T) {
	readErr := errors.New("connection reset")
	writeErr := errors.New("disk full")
	err := copyBody(writerFunc(func([]byte) (int, error) { return 0, writeErr }), dataAndError{readErr}, "u")
	if !errors.Is(err, writeErr) || errors.Is(err, ErrDownload) {
		t.Errorf("copyBody() = %v, want the write error", err)
	}
	var buf bytes.Buffer
	if err := copyBody(&buf, dataAndError{readErr}, "u"); !errors.Is(err, ErrDownload) || !errors.Is(err, readErr) {
		t.Errorf("copyBody() = %v, want ErrDownload wrapping the read error", err)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

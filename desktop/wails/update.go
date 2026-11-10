package main

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/enbu-net/enbu/pkg/selfupdate"
)

// appUpdater updates the running desktop app and restarts it.
type appUpdater struct {
	*selfupdate.Updater
	executable string
	quit       func()
}

// newUpdater describes this installation: who updates it, and what an
// update replaces. It also removes what an earlier update left behind.
func newUpdater(version string, quit func()) *appUpdater {
	here := selfupdate.Here(runtime.GOOS, version)
	method := selfupdate.Detect(here)
	target, _ := selfupdate.Target(runtime.GOOS, here.Executable)
	// Without the user's own cache directory there is nowhere private to
	// download to, so updates fail instead of using a shared temp directory.
	cacheDir := ""
	if cache, err := os.UserCacheDir(); err == nil {
		cacheDir = filepath.Join(cache, "enbu", "update")
	}
	if method == selfupdate.MethodSelf {
		selfupdate.CleanUp(target)
	}
	slog.Info("update method", "method", method)
	return &appUpdater{
		Updater: &selfupdate.Updater{
			Client:   &http.Client{Timeout: 10 * time.Minute},
			Method:   method,
			Version:  version,
			GOOS:     runtime.GOOS,
			GOARCH:   runtime.GOARCH,
			Target:   target,
			CacheDir: cacheDir,
		},
		executable: here.Executable,
		quit:       quit,
	}
}

// Restart starts the updated app, which waits for this one to exit and
// release the single-instance lock, and quits.
func (u *appUpdater) Restart() error {
	if err := selfupdate.Relaunch(u.executable); err != nil {
		return err
	}
	u.quit()
	return nil
}

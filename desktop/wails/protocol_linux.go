//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/enbu-net/enbu/assets"
)

const desktopFile = desktopID + ".desktop"

// registerProtocolHandler makes enbu:// links and the app menu open this
// executable, for installs that did not come from a package (the release
// tar.gz, a local build). A package installs the entry system-wide, so then
// there is nothing to do.
func registerProtocolHandler() error {
	if systemEntryInstalled(os.Getenv("XDG_DATA_DIRS")) {
		return nil
	}
	dataDir, err := linuxUserDataDir()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	// An AppImage runs from a new mount point each time; the image is stable.
	if appImage := os.Getenv("APPIMAGE"); filepath.IsAbs(appImage) {
		executable = appImage
	}
	return registerLinuxProtocolHandler(dataDir, executable, setDefaultHandler)
}

// systemEntryInstalled reports whether a package installed the desktop entry
// in one of the XDG data directories.
func systemEntryInstalled(xdgDataDirs string) bool {
	if xdgDataDirs == "" {
		xdgDataDirs = "/usr/local/share:/usr/share"
	}
	for _, dir := range filepath.SplitList(xdgDataDirs) {
		if !filepath.IsAbs(dir) {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "applications", desktopFile)); err == nil {
			return true
		}
	}
	return false
}

// setDefaultHandler makes the entry the handler of enbu:// links, unless it
// already is, so that a choice the user made in between is not overwritten on
// every launch.
func setDefaultHandler() error {
	current, err := exec.Command("xdg-mime", "query", "default", "x-scheme-handler/enbu").Output()
	if err == nil && strings.TrimSpace(string(current)) == desktopFile {
		return nil
	}
	output, err := exec.Command("xdg-mime", "default", desktopFile, "x-scheme-handler/enbu").CombinedOutput()
	if err != nil {
		return fmt.Errorf("setting default URI handler: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func linuxUserDataDir() (string, error) {
	if dataDir := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(dataDir) {
		return dataDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share"), nil
}

// registerLinuxProtocolHandler writes the per-user desktop entry and icon,
// each only when it changed, then makes the entry the enbu:// handler.
func registerLinuxProtocolHandler(dataDir, executable string, setDefault func() error) error {
	applicationsDir := filepath.Join(dataDir, "applications")
	entry := fmt.Sprintf("[Desktop Entry]\nType=Application\nName=enbu\nComment=Keyless .env management\n"+
		"Exec=%s %%u\nIcon=%s\nTerminal=false\nCategories=Development;Security;Utility;\n"+
		"MimeType=x-scheme-handler/enbu;\nStartupWMClass=%s\n", quoteDesktopExec(executable), desktopID, desktopID)
	if err := writeIfChanged(filepath.Join(applicationsDir, desktopFile), []byte(entry)); err != nil {
		return fmt.Errorf("writing desktop entry: %w", err)
	}
	icon := filepath.Join(dataDir, "icons", "hicolor", "512x512", "apps", desktopID+".png")
	if err := writeIfChanged(icon, assets.Icon); err != nil {
		return fmt.Errorf("writing icon: %w", err)
	}
	return setDefault()
}

// writeIfChanged writes data to path unless path already holds it.
func writeIfChanged(path string, data []byte) error {
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, data) {
		return nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func quoteDesktopExec(value string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"`", "\\`",
		"$", `\$`,
		"%", "%%",
	)
	return `"` + replacer.Replace(value) + `"`
}

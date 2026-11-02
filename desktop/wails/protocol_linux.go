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
// tar.gz, a local build). A package installs the entry system-wide; then a
// per-user entry from an earlier run would shadow it, so it is removed.
func registerProtocolHandler() error {
	dataDir, err := linuxUserDataDir()
	if err != nil {
		return err
	}
	if systemEntryInstalled(os.Getenv("XDG_DATA_DIRS")) {
		if err := removeUserEntry(dataDir); err != nil {
			return err
		}
		return setDefaultHandler()
	}
	executable, err := launcher()
	if err != nil {
		return err
	}
	return registerLinuxProtocolHandler(dataDir, executable, setDefaultHandler)
}

// launcher is the file the desktop entry runs.
func launcher() (string, error) {
	// An AppImage runs from a new mount point each time; the image is stable.
	if appImage := os.Getenv("APPIMAGE"); filepath.IsAbs(appImage) {
		return appImage, nil
	}
	return os.Executable()
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
	if err := writeIfChanged(userEntryPath(dataDir), []byte(userEntry(executable))); err != nil {
		return fmt.Errorf("writing desktop entry: %w", err)
	}
	if err := writeIfChanged(userIconPath(dataDir), assets.Icon); err != nil {
		return fmt.Errorf("writing icon: %w", err)
	}
	return setDefault()
}

func userEntryPath(dataDir string) string {
	return filepath.Join(dataDir, "applications", desktopFile)
}

func userIconPath(dataDir string) string {
	return filepath.Join(dataDir, "icons", "hicolor", "512x512", "apps", desktopID+".png")
}

func userEntry(executable string) string {
	return fmt.Sprintf("[Desktop Entry]\nType=Application\nName=enbu\nComment=Keyless .env management\n"+
		"Exec=%s %%u\nIcon=%s\nTerminal=false\nCategories=Development;Security;Utility;\n"+
		"MimeType=x-scheme-handler/enbu;\nStartupWMClass=%s\n", quoteDesktopExec(executable), desktopID, desktopID)
}

// removeUserEntry removes the per-user entry and icon that
// registerLinuxProtocolHandler wrote, whatever executable the entry named.
// Files the user changed are left alone.
func removeUserEntry(dataDir string) error {
	entryPath := userEntryPath(dataDir)
	entry, err := os.ReadFile(entryPath)
	if err == nil && withoutExec(string(entry)) == withoutExec(userEntry("")) {
		if err := os.Remove(entryPath); err != nil {
			return fmt.Errorf("removing desktop entry: %w", err)
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	iconPath := userIconPath(dataDir)
	icon, err := os.ReadFile(iconPath)
	if err == nil && bytes.Equal(icon, assets.Icon) {
		if err := os.Remove(iconPath); err != nil {
			return fmt.Errorf("removing icon: %w", err)
		}
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func withoutExec(entry string) string {
	lines := strings.Split(entry, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !strings.HasPrefix(line, "Exec=") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
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

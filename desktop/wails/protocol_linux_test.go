//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/enbu-net/enbu/assets"
)

func TestRegisterLinuxProtocolHandler(t *testing.T) {
	dataDir := t.TempDir()
	called := 0
	setDefault := func() error {
		called++
		return nil
	}
	if err := registerLinuxProtocolHandler(dataDir, `/opt/enbu build/enbu%desktop`, setDefault); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatal("default URI handler was not set")
	}
	entryPath := filepath.Join(dataDir, "applications", "net.enbu.desktop.desktop")
	data, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	entry := string(data)
	for _, want := range []string{
		`Exec="/opt/enbu build/enbu%%desktop" %u`,
		`MimeType=x-scheme-handler/enbu;`,
		`Icon=net.enbu.desktop`,
		`StartupWMClass=net.enbu.desktop`,
	} {
		if !strings.Contains(entry, want) {
			t.Fatalf("desktop entry does not contain %q:\n%s", want, entry)
		}
	}
	if strings.Contains(entry, "NoDisplay") {
		t.Fatalf("the entry must show in the app menu:\n%s", entry)
	}
	icon, err := os.ReadFile(filepath.Join(dataDir, "icons", "hicolor", "512x512", "apps", "net.enbu.desktop.png"))
	if err != nil || !bytes.Equal(icon, assets.Icon) {
		t.Fatalf("icon not written: %v", err)
	}

	// A second launch leaves unchanged files alone.
	old := time.Unix(1_000_000_000, 0)
	if err := os.Chtimes(entryPath, old, old); err != nil {
		t.Fatal(err)
	}
	if err := registerLinuxProtocolHandler(dataDir, `/opt/enbu build/enbu%desktop`, setDefault); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(entryPath); err != nil || !st.ModTime().Equal(old) {
		t.Fatalf("unchanged entry was rewritten: %v", err)
	}
}

func TestSystemEntryInstalled(t *testing.T) {
	system := t.TempDir()
	empty := t.TempDir()
	dirs := "relative:" + empty + string(os.PathListSeparator) + system
	if systemEntryInstalled(dirs) {
		t.Fatal("no entry installed yet")
	}
	if err := os.MkdirAll(filepath.Join(system, "applications"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(system, "applications", "net.enbu.desktop.desktop"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !systemEntryInstalled(dirs) {
		t.Fatal("the packaged entry was not found")
	}
}

// The packaged entry names the binary the package installs and the same ID.
func TestPackagedDesktopEntry(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("packaging", "linux", "net.enbu.desktop.desktop"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Exec=enbu-desktop %u", "Icon=" + desktopID, "StartupWMClass=" + desktopID, "MimeType=x-scheme-handler/enbu;"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("packaged entry does not contain %q", want)
		}
	}
}

func TestRemoveUserEntry(t *testing.T) {
	dataDir := t.TempDir()
	if err := registerLinuxProtocolHandler(dataDir, "/old/place/enbu-desktop", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := removeUserEntry(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{userEntryPath(dataDir), userIconPath(dataDir)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s was not removed: %v", path, err)
		}
	}
	// Nothing to remove is fine.
	if err := removeUserEntry(dataDir); err != nil {
		t.Fatal(err)
	}

	// An entry the user edited stays.
	edited := userEntry("/opt/enbu") + "NoDisplay=true\n"
	if err := os.MkdirAll(filepath.Dir(userEntryPath(dataDir)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userEntryPath(dataDir), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeUserEntry(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(userEntryPath(dataDir)); err != nil {
		t.Fatalf("edited entry was removed: %v", err)
	}
}

func TestLauncherPrefersAppImage(t *testing.T) {
	t.Setenv("APPIMAGE", "/home/kota/Apps/enbu.AppImage")
	if got, err := launcher(); err != nil || got != "/home/kota/Apps/enbu.AppImage" {
		t.Fatalf("launcher() = %q, %v", got, err)
	}
	t.Setenv("APPIMAGE", "relative.AppImage")
	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := launcher(); err != nil || got != want {
		t.Fatalf("launcher() = %q, %v, want %q", got, err, want)
	}
}

// fakeXDGMime puts an xdg-mime on PATH that answers query with current and
// logs every call.
func fakeXDGMime(t *testing.T, current string) (log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\nif [ \"$1\" = query ]; then echo " + current + "; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "xdg-mime"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return log
}

func TestSetDefaultHandler(t *testing.T) {
	for _, tt := range []struct {
		current string
		want    string
	}{
		{desktopFile, "query default x-scheme-handler/enbu\n"},
		{"other.desktop", "query default x-scheme-handler/enbu\ndefault " + desktopFile + " x-scheme-handler/enbu\n"},
	} {
		log := fakeXDGMime(t, tt.current)
		if err := setDefaultHandler(); err != nil {
			t.Fatal(err)
		}
		calls, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		if string(calls) != tt.want {
			t.Fatalf("with %s as default, xdg-mime calls:\n%s\nwant:\n%s", tt.current, calls, tt.want)
		}
	}
}

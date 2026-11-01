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

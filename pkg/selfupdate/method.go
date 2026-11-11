// Package selfupdate finds the desktop app's newest release, verifies it with
// the release's Sigstore signature, and installs it over the running app when
// enbu manages the installation itself.
package selfupdate

import (
	"path/filepath"
	"strings"

	"golang.org/x/mod/semver"
)

// Method says who updates an installation, and so what the app may offer.
type Method string

const (
	// MethodSelf: unpacked from a release archive into a place this user may
	// write; the app replaces itself.
	MethodSelf Method = "self"
	// MethodHomebrew: installed with Homebrew; `brew upgrade` updates it.
	MethodHomebrew Method = "homebrew"
	// MethodSystemPackage: installed from the .deb or .rpm; the system's
	// package manager updates it.
	MethodSystemPackage Method = "system_package"
	// MethodEditor: the enbu binary inside an editor extension (VS Code),
	// which the editor's extension updates replace.
	MethodEditor Method = "editor"
	// MethodDevelopment: a build without a release version.
	MethodDevelopment Method = "development"
	// MethodManual: a release build in a place this user may not write;
	// the person downloads the release.
	MethodManual Method = "manual"
)

// Installation is what Detect looks at; the fields are inputs so that tests
// can describe any machine.
type Installation struct {
	GOOS       string
	Version    string
	Executable string // the running binary, symlinks resolved
	// Writable reports whether this user may create and rename files in dir.
	Writable func(dir string) bool
	// Exists reports whether a path exists.
	Exists func(path string) bool
}

// Detect decides who updates the installation. The checks go from the most
// specific to the most general: a build without a release version never
// updates, a package manager's files belong to it, and only then may the app
// replace itself where it can write.
func Detect(in Installation) Method {
	if !IsRelease(in.Version) {
		return MethodDevelopment
	}
	exe := filepath.ToSlash(in.Executable)
	if strings.Contains(exe, "/Cellar/") || strings.Contains(exe, "/Caskroom/") || homebrewCask(in) {
		return MethodHomebrew
	}
	if in.GOOS == "linux" && systemPackagePath(exe) {
		return MethodSystemPackage
	}
	target, ok := Target(in.GOOS, in.Executable)
	if !ok || in.Writable == nil || !in.Writable(filepath.Dir(target)) {
		return MethodManual
	}
	return MethodSelf
}

// IsRelease reports whether version names a release (vMAJOR.MINOR.PATCH,
// without a prerelease or build suffix such as -dirty).
func IsRelease(version string) bool {
	return semver.IsValid(version) && semver.Canonical(version) == version && semver.Prerelease(version) == ""
}

// Newer reports whether latest is a newer release than current.
func Newer(current, latest string) bool {
	return IsRelease(current) && IsRelease(latest) && semver.Compare(latest, current) > 0
}

// Target is what an update replaces: the .app bundle on macOS, the binary
// elsewhere. ok is false for a macOS binary outside an app bundle.
func Target(goos, executable string) (string, bool) {
	if goos != "darwin" {
		return executable, true
	}
	macos := filepath.Dir(executable)
	contents := filepath.Dir(macos)
	bundle := filepath.Dir(contents)
	if filepath.Base(macos) != "MacOS" || filepath.Base(contents) != "Contents" || filepath.Ext(bundle) != ".app" {
		return "", false
	}
	return bundle, true
}

// homebrewCask reports whether a Homebrew cask installed this app bundle:
// the cask moves the .app to /Applications and keeps its record in Caskroom.
func homebrewCask(in Installation) bool {
	if in.GOOS != "darwin" || in.Exists == nil {
		return false
	}
	for _, prefix := range []string{"/opt/homebrew", "/usr/local"} {
		if in.Exists(prefix + "/Caskroom/" + caskName) {
			return true
		}
	}
	return false
}

// caskName is the desktop app's cask in enbu-net/homebrew-tap.
const caskName = "enbu-desktop"

// systemPackagePath reports whether a Linux binary lives where the .deb and
// .rpm install it, or anywhere else a package manager owns.
func systemPackagePath(exe string) bool {
	for _, dir := range []string{"/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/usr/share/", "/opt/"} {
		if strings.HasPrefix(exe, dir) {
			return true
		}
	}
	return false
}

package config

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// DataDir is enbu's per-user data directory. It is always absolute: a relative
// path would put identities and checkpoints under the working directory, which
// is usually a Git repository. XDG_DATA_HOME is used only when absolute, as the
// XDG Base Directory specification requires.
func DataDir() string {
	return dataDir(runtime.GOOS, os.Getenv, homeDir)
}

func dataDir(goos string, getenv func(string) string, home func() string) string {
	if xdg := getenv("XDG_DATA_HOME"); filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "enbu")
	}
	switch goos {
	case "darwin":
		return filepath.Join(home(), "Library", "Application Support", "enbu")
	case "windows":
		if local := getenv("LOCALAPPDATA"); filepath.IsAbs(local) {
			return filepath.Join(local, "enbu")
		}
		return filepath.Join(home(), "AppData", "Local", "enbu")
	default:
		return filepath.Join(home(), ".local", "share", "enbu")
	}
}

// unresolvedHome stands in for a home directory that cannot be found. It is
// absolute, so nothing lands in the working directory, and it does not exist,
// so reads find nothing and writes fail instead of going somewhere unexpected.
// On Windows it sits on the drive of the temporary directory, because a path
// without a drive letter is not absolute there.
var unresolvedHome = filepath.VolumeName(os.TempDir()) + string(filepath.Separator) + "nonexistent"

// homeDir is the user's home directory: $HOME (or %USERPROFILE%) when it is
// absolute, otherwise the home directory in the user database, which cron jobs,
// some services and `env -i` still have when HOME is unset.
func homeDir() string {
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		return home
	}
	if u, err := user.Current(); err == nil && filepath.IsAbs(u.HomeDir) {
		return u.HomeDir
	}
	return unresolvedHome
}

// DefaultDataDir is the data directory DataDir names when XDG_DATA_HOME is
// not set.
func DefaultDataDir() string {
	return dataDir(runtime.GOOS, func(name string) string {
		if name == "XDG_DATA_HOME" {
			return ""
		}
		return os.Getenv(name)
	}, homeDir)
}

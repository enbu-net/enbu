package fsutil

import (
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/text/unicode/norm"
)

// Canonical returns one spelling of path, so that the same folder reached
// from the CLI, a folder picker and git compares equal: absolute and clean,
// with symbolic links resolved when it exists (on Windows that also gives the
// on-disk letter case and long names instead of 8.3 short names). On macOS,
// whose file systems match a name in any Unicode normalization, it is NFC,
// the form git (core.precomposeUnicode) and typed input use, while a picker or
// an archive may hand over NFD. The result still opens the same file.
func Canonical(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	path = filepath.Clean(path)
	if runtime.GOOS == "darwin" {
		// A volume that does not fold normalization (SMB, NFS, exFAT) keeps
		// the spelling that opens the folder, also when another folder has
		// the NFC name.
		if nfc := norm.NFC.String(path); nfc != path && sameOrMissing(path, nfc) {
			path = nfc
		}
	}
	return path
}

// sameOrMissing reports whether path does not exist or names the same file
// as other.
func sameOrMissing(path, other string) bool {
	a, err := os.Lstat(path)
	if err != nil {
		return true
	}
	b, err := os.Lstat(other)
	return err == nil && os.SameFile(a, b)
}

package fsutil

import (
	"io/fs"
	"os"
	"path/filepath"
)

// MkdirAll creates directories and syncs each new directory and its parent
// before returning. Callers can safely persist a reference to files inside it.
func MkdirAll(path string, perm fs.FileMode) error {
	path = filepath.Clean(path)
	var created []string
	for dir := path; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(dir); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		created = append(created, dir)
		if filepath.Dir(dir) == dir {
			break
		}
	}
	if err := os.MkdirAll(path, perm); err != nil {
		return err
	}
	for _, dir := range created {
		if err := syncDir(dir); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	return nil
}

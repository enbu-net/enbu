package fsutil

import (
	"errors"
	"os"
	"path/filepath"
)

// TempPrefix starts the name of every temporary file WriteFileAtomic creates.
const TempPrefix = ".enbu-tmp-"

// AtomicOptions adjusts WriteFileAtomicWith.
type AtomicOptions struct {
	// Prepare runs on the temporary file before its mode is set and data is
	// written, for example to give it the owner of the file it replaces.
	Prepare func(*os.File) error
	// BeforeRename runs once data is synced and the file closed. An error
	// leaves path untouched.
	BeforeRename func() error
}

// WriteFileAtomic replaces path with data through a synced temporary file in
// the same directory, which then gets mode perm. A failure leaves the old file
// intact, and a reader sees either the old content or the new, never part.
// The directory must exist.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return WriteFileAtomicWith(path, data, perm, AtomicOptions{})
}

// WriteFileAtomicWith is WriteFileAtomic with the steps of opts.
func WriteFileAtomicWith(path string, data []byte, perm os.FileMode, opts AtomicOptions) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), TempPrefix+"*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if opts.Prepare != nil {
		err = opts.Prepare(tmp)
	}
	if err == nil {
		err = tmp.Chmod(perm)
	}
	if err == nil {
		if _, err = tmp.Write(data); err == nil {
			err = tmp.Sync()
		}
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	if opts.BeforeRename != nil {
		if err := opts.BeforeRename(); err != nil {
			return err
		}
	}
	return Rename(tmp.Name(), path)
}

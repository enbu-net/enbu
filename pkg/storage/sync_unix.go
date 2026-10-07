//go:build unix && fixture

package storage

import "os"

func syncDirectory(r *os.Root) error {
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

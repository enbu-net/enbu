package app

import (
	"context"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/fsutil"
)

// writePrivateOutput replaces the directory entry instead of truncating its
// inode: existing public modes and hard/symbolic links must not expose secrets
// or modify another file. Failures before rename leave the old output intact.
func writePrivateOutput(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".enbu-output-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fsutil.Rename(f.Name(), path)
}

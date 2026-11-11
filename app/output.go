package app

import (
	"context"

	"github.com/enbu-net/enbu/pkg/fsutil"
)

// writePrivateOutput replaces the directory entry instead of truncating its
// inode: existing public modes and hard/symbolic links must not expose secrets
// or modify another file. Failures before rename leave the old output intact.
func writePrivateOutput(ctx context.Context, path string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fsutil.WriteFileAtomicWith(path, data, 0o600, fsutil.AtomicOptions{BeforeRename: ctx.Err})
}

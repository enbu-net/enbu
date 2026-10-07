//go:build !unix

package storage

import "os"

// Windows does not support syncing directory handles with os.File.Sync.
func syncDirectory(_ *os.Root) error { return nil }

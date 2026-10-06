//go:build !unix && !windows

package wsp

import "os"

// Platforms without file locking (such as the browser demo) have one process
// per checkpoint file, and the in-process mutex is enough.
func tryLock(*os.File) (bool, error) { return true, nil }

func unlock(*os.File) {}

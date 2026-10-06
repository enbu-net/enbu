package apptest

import (
	"os"
	"testing"
)

// IsolateDataDir runs the tests with XDG_DATA_HOME pointing at a throwaway
// directory, so checkpoints and local state never touch the real per-user data
// directory, and returns the exit code. Use it as:
//
//	func TestMain(m *testing.M) { os.Exit(apptest.IsolateDataDir(m)) }
//
// pkg/config reads XDG_DATA_HOME first on every platform.
func IsolateDataDir(m *testing.M) int {
	dir, err := os.MkdirTemp("", "enbu-test-data-")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Setenv("XDG_DATA_HOME", dir); err != nil {
		panic(err)
	}
	return m.Run()
}

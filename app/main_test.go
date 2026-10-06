package app

import (
	"os"
	"testing"
)

// Keep tests away from the real per-user data directory, where checkpoints and
// local state would otherwise accumulate.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "enbu-test-data-")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("XDG_DATA_HOME", dir); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

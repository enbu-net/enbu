//go:build scenario

package test

import (
	"os"
	"testing"
)

// Keep scenario runs away from the real per-user data directory, where local
// rollback checkpoints would otherwise accumulate.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "enbu-scenario-data-")
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

//go:build scenario

package test

import (
	"os"
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
)

// Keep scenario runs away from the real per-user data directory.
func TestMain(m *testing.M) { os.Exit(apptest.IsolateDataDir(m)) }

package desktop

import (
	"os"
	"testing"

	"github.com/enbu-net/enbu/app/apptest"
)

// Keep tests away from the real per-user data directory.
func TestMain(m *testing.M) { os.Exit(apptest.IsolateDataDir(m)) }

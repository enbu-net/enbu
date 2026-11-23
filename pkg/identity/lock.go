package identity

import (
	"os"

	"github.com/enbu-net/enbu/pkg/fsutil"
)

func acquireCreationLock(path string) (*os.File, error) {
	return fsutil.LockFile(path, false)
}

//go:build fixture

package app

import (
	"net/url"
	"path/filepath"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
)

// openLocalStorage opens the filesystem backend. It exists only in fixture
// builds (tests and E2E); release binaries do not accept local:// URLs.
func openLocalStorage(u *url.URL) (*storage.Store, error) {
	if u.Host != "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "local URL must have an empty host", nil)
	}
	path := u.Path
	if len(path) > 2 && path[0] == '/' && path[2] == ':' {
		path = path[1:]
	}
	dir := filepath.FromSlash(path)
	if !filepath.IsAbs(dir) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "local storage requires an absolute path", nil)
	}
	return storage.NewLocal(dir), nil
}

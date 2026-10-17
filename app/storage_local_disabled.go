//go:build !fixture

package app

import (
	"net/url"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
)

func openLocalStorage(*url.URL) (storage.Store, error) {
	return nil, apperr.New(apperr.CodeInvalidArgument, "storage must be specified with oci:// or s3://", nil)
}

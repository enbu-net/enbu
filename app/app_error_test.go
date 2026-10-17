package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
	"github.com/opencontainers/go-digest"
)

func TestExportedOperationNormalizesUnknownError(t *testing.T) {
	cause := errors.New("backend failed")
	a := newTestApp(t, "owner", "repo", "default", mustKeyPair(t), nil)
	a.Storage = storagetest.Wrap(a.Storage, storagetest.Hooks{
		Fetch: func(context.Context, storage.Store, storage.Kind, string, digest.Digest) (storage.Object, error) {
			return storage.Object{}, cause
		},
	})
	_, err := a.ListRecipients(context.Background())
	var appErr *apperr.Error
	if !errors.As(err, &appErr) {
		t.Fatalf("ListRecipients() error = %T, want *apperr.Error", err)
	}
	if appErr.Code() != apperr.CodeInternal {
		t.Fatalf("code = %q", appErr.Code())
	}
	if !errors.Is(err, cause) {
		t.Fatal("normalized error does not preserve the cause")
	}
}

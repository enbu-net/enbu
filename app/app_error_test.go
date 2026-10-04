package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/storage/storagetest"
)

type failingStorage struct {
	storagetest.Objects
	cause error
}

func (s *failingStorage) Get(context.Context, string) ([]byte, storage.Version, error) {
	return nil, "", s.cause
}

func TestExportedOperationNormalizesUnknownError(t *testing.T) {
	cause := errors.New("backend failed")
	a := &App{Storage: newMemRegistry()}
	prepareApp(t, a, "default")
	a.Storage = storagetest.FromObjects(&failingStorage{cause: cause})
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

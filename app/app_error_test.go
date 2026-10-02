package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/storage"
)

type failingStorage struct {
	storage.Storage
	cause error
}

func (s *failingStorage) Get(context.Context, string) (storage.Object, storage.Version, error) {
	return storage.Object{}, "", s.cause
}

func TestExportedOperationNormalizesUnknownError(t *testing.T) {
	cause := errors.New("backend failed")
	a := &App{Storage: newMemRegistry()}
	prepareApp(t, a, "default")
	a.Storage = &failingStorage{cause: cause}
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

func TestConflictRetriesExhaustedPreservesCodeAndCause(t *testing.T) {
	cause := apperr.New(apperr.CodeConflict, "version mismatch", nil)
	err := conflictRetriesExhausted(cause, maxRetries)
	if !apperr.Is(err, apperr.CodeConflict) {
		t.Fatalf("code = %q", apperr.CodeOf(err))
	}
	if !errors.Is(err, cause) {
		t.Fatal("retry exhaustion does not preserve the conflict cause")
	}
}

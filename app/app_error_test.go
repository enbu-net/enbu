package app

import (
	"context"
	"errors"
	"testing"

	"github.com/enbu-net/enbu/apperr"
)

type failingTokenProvider struct {
	err error
}

func (p failingTokenProvider) LoadToken() (string, string, error) {
	return "", "", p.err
}

func TestExportedOperationNormalizesUnknownError(t *testing.T) {
	cause := errors.New("backend failed")
	a := &App{TokenProvider: failingTokenProvider{err: cause}}

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

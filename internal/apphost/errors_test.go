package apphost

import (
	"errors"
	"testing"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/registry"
)

func TestNormalizeErrorClassifiesOnlyStableClientConditions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		code apperr.Code
	}{
		{name: "not initialized", err: ErrNotInitialized, code: apperr.CodeNotInitialized},
		{name: "state conflict", err: ErrStateConflict, code: apperr.CodeConflict},
		{name: "registry conflict", err: registry.ErrAnnouncementConflict, code: apperr.CodeConflict},
		{name: "invalid action", err: host.ErrInvalidAction, code: apperr.CodeInvalidArgument},
		{name: "unknown", err: errors.New("token=secret"), code: apperr.CodeInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := apperr.CodeOf(NormalizeError(test.err)); got != test.code {
				t.Fatalf("NormalizeError() code = %q, want %q", got, test.code)
			}
		})
	}
}

func TestNormalizeErrorPreservesExistingApplicationError(t *testing.T) {
	t.Parallel()
	cause := errors.New("cause")
	original := apperr.Wrap(apperr.CodeAccessDenied, "denied", cause, nil)
	normalized := NormalizeError(original)
	if apperr.CodeOf(normalized) != apperr.CodeAccessDenied || !errors.Is(normalized, cause) {
		t.Fatalf("NormalizeError() = %v", normalized)
	}
}

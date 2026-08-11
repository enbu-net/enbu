package apphost

import (
	"errors"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/host"
	"github.com/enbu-net/enbu/pkg/registry"
	"github.com/enbu-net/enbu/pkg/workspace"
)

// NormalizeError is the single classification boundary shared by CLI and
// desktop clients. Internal packages retain ordinary errors and cause chains;
// only errors crossing a client boundary receive a stable public code.
func NormalizeError(err error) error {
	if err == nil {
		return nil
	}
	var applicationError *apperr.Error
	if errors.As(err, &applicationError) {
		return apperr.Normalize(err)
	}
	switch {
	case errors.Is(err, ErrNotInitialized), errors.Is(err, ErrInitializationIncomplete), errors.Is(err, workspace.ErrConfigNotFound):
		return apperr.Wrap(apperr.CodeNotInitialized, "workspace is not initialized", err, nil)
	case errors.Is(err, ErrAlreadyInitialized), errors.Is(err, ErrStateConflict), errors.Is(err, registry.ErrAnnouncementConflict):
		return apperr.Wrap(apperr.CodeConflict, "workspace state changed", err, nil)
	case errors.Is(err, host.ErrInvalidAction), errors.Is(err, host.ErrInvalidHandle),
		errors.Is(err, host.ErrInvalidQuery), errors.Is(err, host.ErrInvalidQueryCursor),
		errors.Is(err, workspace.ErrInvalidConfig), errors.Is(err, workspace.ErrLegacyConfig),
		errors.Is(err, workspace.ErrUnsafeConfigPath):
		return apperr.Wrap(apperr.CodeInvalidArgument, "invalid workspace request", err, nil)
	default:
		return apperr.Normalize(err)
	}
}

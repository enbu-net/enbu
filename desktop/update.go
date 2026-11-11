package desktop

import (
	"context"
	"errors"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/selfupdate"
)

// AppUpdater checks for and installs releases of the running desktop app.
// The desktop app sets one; editor extensions (enbu rpc) have none, since
// the editor updates them.
type AppUpdater interface {
	Check(ctx context.Context) (selfupdate.Status, error)
	Update(ctx context.Context) (selfupdate.Status, error)
	// Restart starts the updated app and quits this one.
	Restart() error
}

// UpdateStatus is what the settings screen shows about updates.
type UpdateStatus = selfupdate.Status

// CheckForUpdate compares the running app with the newest release. Without
// an updater the app is an editor extension's, which the editor updates.
func (s *Service) CheckForUpdate() (UpdateStatus, error) {
	if s.updater == nil {
		return UpdateStatus{Method: selfupdate.MethodEditor, Current: s.GetAppVersion()}, nil
	}
	status, err := s.updater.Check(s.context())
	return status, publicError(updateError(err))
}

// InstallUpdate downloads, verifies and installs the newest release over
// the running app, when the app manages its own installation. One update
// runs at a time.
func (s *Service) InstallUpdate() (UpdateStatus, error) {
	if s.updater == nil {
		return UpdateStatus{Method: selfupdate.MethodEditor, Current: s.GetAppVersion()}, publicError(apperr.New(apperr.CodeInvalidArgument, "the editor updates this app", nil))
	}
	if !s.updateMu.TryLock() {
		return UpdateStatus{}, publicError(apperr.New(apperr.CodeConflict, "an update is already running", nil))
	}
	defer s.updateMu.Unlock()
	status, err := s.updater.Update(s.context())
	return status, publicError(updateError(err))
}

// RestartApp starts the installed update and quits.
func (s *Service) RestartApp() error {
	if s.updater == nil {
		return publicError(apperr.New(apperr.CodeInvalidArgument, "the editor restarts this app", nil))
	}
	return publicError(updateError(s.updater.Restart()))
}

// updateError gives the UI a code it can act on: a failed verification is
// told apart from a failed download, which can be retried.
func updateError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, selfupdate.ErrUnverified):
		return apperr.Wrap(apperr.CodeUpdateUnverified, "update failed verification", err, nil)
	case errors.Is(err, selfupdate.ErrNotSelfManaged):
		return apperr.Wrap(apperr.CodeInvalidArgument, "this installation is updated elsewhere", err, nil)
	case errors.Is(err, selfupdate.ErrDownload):
		return apperr.Wrap(apperr.CodeUnavailable, "the release could not be downloaded", err, nil)
	default:
		return apperr.Normalize(err)
	}
}

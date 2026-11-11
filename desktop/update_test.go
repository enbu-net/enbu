package desktop

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/enbu-net/enbu/pkg/selfupdate"
)

type fakeUpdater struct {
	status    selfupdate.Status
	err       error
	updates   int
	restarted bool
	started   chan struct{}
	block     chan struct{}
}

func (f *fakeUpdater) Check(context.Context) (selfupdate.Status, error) { return f.status, f.err }

func (f *fakeUpdater) Update(context.Context) (selfupdate.Status, error) {
	f.updates++
	if f.block != nil {
		f.started <- struct{}{}
		<-f.block
	}
	return f.status, f.err
}

func (f *fakeUpdater) Restart() error {
	f.restarted = true
	return f.err
}

func TestUpdateWithoutUpdaterIsTheEditors(t *testing.T) {
	s := NewService(app.New(clock.New()))
	s.AppVersion = "v0.9.0"
	status, err := s.CheckForUpdate()
	if err != nil || status.Method != selfupdate.MethodEditor || status.Current != "v0.9.0" {
		t.Errorf("CheckForUpdate() = %+v, %v", status, err)
	}
	if _, err := s.InstallUpdate(); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Errorf("InstallUpdate() = %v, want invalid_argument", err)
	}
	if err := s.RestartApp(); !apperr.Is(err, apperr.CodeInvalidArgument) {
		t.Errorf("RestartApp() = %v, want invalid_argument", err)
	}
}

func TestUpdateErrorsCarryCodes(t *testing.T) {
	tests := []struct {
		err  error
		code apperr.Code
	}{
		{fmt.Errorf("%w: bad signature", selfupdate.ErrUnverified), apperr.CodeUpdateUnverified},
		{fmt.Errorf("%w: offline", selfupdate.ErrDownload), apperr.CodeUnavailable},
		{selfupdate.ErrNotSelfManaged, apperr.CodeInvalidArgument},
		{errors.New("disk full"), apperr.CodeInternal},
	}
	for _, tt := range tests {
		s := NewService(app.New(clock.New()))
		s.updater = (&fakeUpdater{err: tt.err})
		if _, err := s.CheckForUpdate(); !apperr.Is(err, tt.code) {
			t.Errorf("CheckForUpdate(%v) = %v, want %s", tt.err, err, tt.code)
		}
		if _, err := s.InstallUpdate(); !apperr.Is(err, tt.code) {
			t.Errorf("InstallUpdate(%v) = %v, want %s", tt.err, err, tt.code)
		}
	}
}

func TestInstallUpdateRunsOneAtATime(t *testing.T) {
	s := NewService(app.New(clock.New()))
	fake := &fakeUpdater{
		status:  selfupdate.Status{Method: selfupdate.MethodSelf},
		started: make(chan struct{}),
		block:   make(chan struct{}),
	}
	s.updater = (fake)
	done := make(chan error)
	go func() {
		_, err := s.InstallUpdate()
		done <- err
	}()
	<-fake.started
	if _, err := s.InstallUpdate(); !apperr.Is(err, apperr.CodeConflict) {
		t.Errorf("second InstallUpdate() = %v, want conflict", err)
	}
	close(fake.block)
	if err := <-done; err != nil {
		t.Errorf("first InstallUpdate() = %v", err)
	}
}

func TestRestartApp(t *testing.T) {
	s := NewService(app.New(clock.New()))
	fake := &fakeUpdater{}
	s.updater = (fake)
	if err := s.RestartApp(); err != nil || !fake.restarted {
		t.Errorf("RestartApp() = %v, restarted %v", err, fake.restarted)
	}
}

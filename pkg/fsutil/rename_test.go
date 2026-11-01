package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var errBusy = errors.New("busy")

func isBusy(err error) bool { return errors.Is(err, errBusy) }

func TestRetryStopsOnSuccess(t *testing.T) {
	calls := 0
	var slept []time.Duration
	err := retry(func() error {
		calls++
		if calls < 3 {
			return errBusy
		}
		return nil
	}, isBusy, func(d time.Duration) { slept = append(slept, d) })
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
	if want := []time.Duration{renameBackoff, 2 * renameBackoff}; len(slept) != 2 || slept[0] != want[0] || slept[1] != want[1] {
		t.Fatalf("slept %v, want %v", slept, want)
	}
}

func TestRetryGivesUpAfterLimit(t *testing.T) {
	calls := 0
	err := retry(func() error { calls++; return errBusy }, isBusy, func(time.Duration) {})
	if !errors.Is(err, errBusy) {
		t.Fatalf("err = %v, want errBusy", err)
	}
	if calls != renameAttempts {
		t.Fatalf("calls = %d, want %d", calls, renameAttempts)
	}
}

func TestRetryDoesNotRetryPermanentErrors(t *testing.T) {
	permanent := errors.New("permanent")
	calls := 0
	err := retry(func() error { calls++; return permanent }, isBusy, func(time.Duration) { t.Fatal("slept on a permanent error") })
	if !errors.Is(err, permanent) || calls != 1 {
		t.Fatalf("err = %v after %d calls, want permanent after 1", err, calls)
	}
}

func TestRenameReplacesTarget(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "from"), filepath.Join(dir, "to")
	if err := os.WriteFile(from, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Rename(from, to); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if b, err := os.ReadFile(to); err != nil || string(b) != "new" {
		t.Fatalf("target = %q, %v; want new", b, err)
	}
	if _, err := os.Stat(from); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists: %v", err)
	}
}

func TestRenameReportsMissingSource(t *testing.T) {
	dir := t.TempDir()
	if err := Rename(filepath.Join(dir, "missing"), filepath.Join(dir, "to")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want not exist", err)
	}
}

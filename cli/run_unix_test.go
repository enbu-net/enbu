//go:build unix

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
)

// TestRunSignalHelperProcess is the child of the signal tests. With
// ENBU_TEST_SIGINT_SELF it sends itself SIGINT, which ends it unless SIGINT
// was ignored when it started. With ENBU_TEST_READY it creates that file and
// waits to be signalled.
func TestRunSignalHelperProcess(t *testing.T) {
	if os.Getenv("ENBU_TEST_HELPER") != "1" {
		return
	}
	if os.Getenv("ENBU_TEST_SIGINT_SELF") == "1" {
		_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}
	if ready := os.Getenv("ENBU_TEST_READY"); ready != "" {
		_ = os.WriteFile(ready, nil, 0o600)
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
}

func signalHelper() []string {
	return []string{os.Args[0], "-test.run=^TestRunSignalHelperProcess$"}
}

func requireExit(t *testing.T, err error, code int) {
	t.Helper()
	var exit *apperr.ExitError
	if !errors.As(err, &exit) || exit.Code != code {
		t.Fatalf("err = %v, want exit status %d", err, code)
	}
}

// The command starts with the default SIGINT action, so Ctrl-C stops it,
// and a command ended by a signal reports 128 plus the signal as a shell does.
func TestRunLeavesSIGINTToTheCommand(t *testing.T) {
	_, err := runWith(t, []string{"ENBU_TEST_HELPER=1", "ENBU_TEST_SIGINT_SELF=1"},
		append([]string{"run", "--"}, signalHelper()...)...)
	requireExit(t, err, 128+int(syscall.SIGINT))
}

// SIGTERM sent to enbu alone reaches the command instead of orphaning it.
func TestRunForwardsSIGTERMToTheCommand(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "ready")
	go func() {
		for range 200 {
			if _, err := os.Stat(ready); err == nil {
				_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()
	_, err := runWith(t, []string{"ENBU_TEST_HELPER=1", "ENBU_TEST_READY=" + ready},
		append([]string{"run", "--"}, signalHelper()...)...)
	requireExit(t, err, 128+int(syscall.SIGTERM))
}

// A command that cannot be found ends with 127, as in a shell, not with an
// enbu usage error.
func TestRunReportsAMissingCommandAs127(t *testing.T) {
	_, err := runWith(t, nil, "run", "--", filepath.Join(t.TempDir(), "no-such-command"))
	requireExit(t, err, 127)
	if _, err := runWith(t, nil, "run", "--", t.TempDir()); err == nil {
		t.Fatal("running a directory succeeded")
	} else {
		requireExit(t, err, 126)
	}
}

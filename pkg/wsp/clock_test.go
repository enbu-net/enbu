package wsp

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/jonboulle/clockwork"
)

func TestLockTimeoutUsesInjectedClock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint")
	release, err := lockFile(path, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	c := clockwork.NewFakeClock()
	done := make(chan error, 1)
	go func() {
		unlock, err := lockFile(path, c)
		if err == nil {
			unlock()
		}
		done <- err
	}()
	if err := c.BlockUntilContext(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	c.Advance(lockTimeout + time.Nanosecond)
	if err := <-done; err == nil {
		t.Fatal("contended lock ignored its injected timeout")
	}
}

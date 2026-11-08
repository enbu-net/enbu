package identity

import (
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func TestCallWithTimeoutReturnsResult(t *testing.T) {
	c := clockwork.NewFakeClock()
	ref, nativeErr, err := callWithTimeout(c, time.Second, func() (uintptr, uintptr) { return 7, 9 }, func(uintptr, uintptr) { t.Error("abandoned a completed call") })
	if err != nil || ref != 7 || nativeErr != 9 {
		t.Fatalf("got %d %d %v", ref, nativeErr, err)
	}
}

func TestCallWithTimeoutAbandonsBlockedCall(t *testing.T) {
	c := clockwork.NewFakeClock()
	release := make(chan struct{})
	released := make(chan [2]uintptr, 1)
	done := make(chan error, 1)
	go func() {
		_, _, err := callWithTimeout(c, 20*time.Millisecond, func() (uintptr, uintptr) { <-release; return 3, 4 }, func(ref, nativeErr uintptr) { released <- [2]uintptr{ref, nativeErr} })
		done <- err
	}()
	if err := c.BlockUntilContext(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	c.Advance(20 * time.Millisecond)
	if err := <-done; !errors.Is(err, errNativeTimeout) {
		t.Fatalf("err = %v, want timeout", err)
	}
	close(release)
	if got := <-released; got != [2]uintptr{3, 4} {
		t.Fatalf("released %v", got)
	}
}

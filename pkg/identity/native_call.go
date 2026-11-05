package identity

import (
	"errors"
	"github.com/enbu-net/enbu/pkg/clock"
	"time"
)

// errNativeTimeout reports a framework call that did not return in time.
var errNativeTimeout = errors.New("the call did not return in time")

// callWithTimeout runs call, which returns an object reference and an error
// reference, and gives up after timeout. A call that cannot be interrupted keeps
// running on its own goroutine; when it returns late, abandon releases what it
// produced, so nothing leaks beyond the blocked thread itself.
func callWithTimeout(c clock.Clock, timeout time.Duration, call func() (ref, nativeErr uintptr), abandon func(ref, nativeErr uintptr)) (uintptr, uintptr, error) {
	type result struct{ ref, nativeErr uintptr }
	results := make(chan result)
	abandoned := make(chan struct{})
	go func() {
		ref, nativeErr := call()
		select {
		case results <- result{ref, nativeErr}:
		case <-abandoned:
			abandon(ref, nativeErr)
		}
	}()
	timer := c.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-results:
		return r.ref, r.nativeErr, nil
	case <-timer.Chan():
		close(abandoned)
		return 0, 0, errNativeTimeout
	}
}

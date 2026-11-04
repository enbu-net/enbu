package identity

import (
	"errors"
	"testing"
	"time"
)

func TestCallWithTimeoutReturnsResult(t *testing.T) {
	ref, nativeErr, err := callWithTimeout(time.Second, func() (uintptr, uintptr) { return 7, 9 }, func(uintptr, uintptr) {
		t.Error("abandoned a call that returned in time")
	})
	if err != nil || ref != 7 || nativeErr != 9 {
		t.Fatalf("got %d %d %v", ref, nativeErr, err)
	}
}

func TestCallWithTimeoutAbandonsBlockedCall(t *testing.T) {
	release := make(chan struct{})
	released := make(chan [2]uintptr, 1)
	start := time.Now()
	_, _, err := callWithTimeout(20*time.Millisecond, func() (uintptr, uintptr) {
		<-release
		return 3, 4
	}, func(ref, nativeErr uintptr) { released <- [2]uintptr{ref, nativeErr} })
	if !errors.Is(err, errNativeTimeout) {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("waited for the blocked call")
	}
	close(release)
	select {
	case got := <-released:
		if got != [2]uintptr{3, 4} {
			t.Fatalf("released %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("the late result was not released")
	}
}

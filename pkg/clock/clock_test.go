package clock

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func TestTimeoutUsesClockAndPreservesContext(t *testing.T) {
	c := clockwork.NewFakeClockAt(time.Unix(100, 0))
	type key struct{}
	parent := context.WithValue(t.Context(), key{}, "kept")
	ctx, cancel := WithTimeout(parent, c, time.Minute)
	defer cancel()
	child, stopChild := context.WithCancel(ctx)
	defer stopChild()
	if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(c.Now().Add(time.Minute)) || ctx.Value(key{}) != "kept" {
		t.Fatal("deadline or value lost")
	}
	c.Advance(time.Minute - time.Nanosecond)
	if ctx.Err() != nil {
		t.Fatal("expired early")
	}
	c.Advance(time.Nanosecond)
	<-ctx.Done()
	<-child.Done()
	if ctx.Err() != context.DeadlineExceeded || context.Cause(ctx) != context.DeadlineExceeded {
		t.Fatalf("wrong expiry: %v %v", ctx.Err(), context.Cause(ctx))
	}
	if child.Err() != context.DeadlineExceeded || context.Cause(child) != context.DeadlineExceeded {
		t.Fatalf("standard child lost deadline semantics: %v %v", child.Err(), context.Cause(child))
	}
}

func TestParentCancellationAndEarlierDeadline(t *testing.T) {
	for _, cause := range []error{errors.New("parent stopped"), context.DeadlineExceeded} {
		c := clockwork.NewFakeClock()
		parent, stop := context.WithCancelCause(t.Context())
		ctx, cancel := WithTimeout(parent, c, time.Hour)
		stop(cause)
		<-ctx.Done()
		cancel()
		if ctx.Err() != context.Canceled || context.Cause(ctx) != cause {
			t.Fatalf("parent cancellation changed: %v %v", ctx.Err(), context.Cause(ctx))
		}
	}
	c := clockwork.NewFakeClock()
	parent, stop := WithTimeout(t.Context(), c, time.Second)
	defer stop()
	child, cancel := WithTimeout(parent, c, time.Hour)
	defer cancel()
	parentDeadline, _ := parent.Deadline()
	childDeadline, _ := child.Deadline()
	if !childDeadline.Equal(parentDeadline) {
		t.Fatal("parent deadline was extended")
	}
	c.Advance(time.Second)
	<-child.Done()
	if child.Err() != context.DeadlineExceeded {
		t.Fatalf("parent deadline did not expire child: %v", child.Err())
	}
}

func TestImmediateCancellationAndDeadline(t *testing.T) {
	c := clockwork.NewFakeClock()
	parent, stop := context.WithCancel(t.Context())
	stop()
	ctx, cancel := WithTimeout(parent, c, time.Hour)
	defer cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("already canceled parent was ignored")
	}
	ctx, cancel = WithTimeout(t.Context(), c, 0)
	defer cancel()
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatal("elapsed deadline was not immediate")
	}
}

func TestWaitUsesClockAndCancellation(t *testing.T) {
	c := clockwork.NewFakeClock()
	done := make(chan error, 1)
	go func() { done <- Wait(t.Context(), c, time.Minute) }()
	if err := c.BlockUntilContext(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	c.Advance(time.Minute)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() { done <- Wait(ctx, c, time.Hour) }()
	if err := c.BlockUntilContext(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("wait ignored cancellation: %v", err)
	}
}

// readyClock makes both signals ready before Wait reaches its select.
type readyClock struct {
	*clockwork.FakeClock
	cancel context.CancelFunc
}

func (c readyClock) NewTimer(d time.Duration) clockwork.Timer {
	timer := c.FakeClock.NewTimer(d)
	c.cancel()
	c.Advance(d)
	return timer
}
func TestWaitCancellationWinsWhenBothSignalsAreReady(t *testing.T) {
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(t.Context())
		c := readyClock{clockwork.NewFakeClock(), cancel}
		if err := Wait(ctx, c, time.Second); err != context.Canceled {
			t.Fatalf("both ready: got %v", err)
		}
	}
}

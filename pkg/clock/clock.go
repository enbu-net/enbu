// Package clock defines the application's time dependency. time.Time and
// time.Duration remain value types; reading time and scheduling work use Clock.
package clock

import (
	"context"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
)

type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) clockwork.Timer
	AfterFunc(time.Duration, func()) clockwork.Timer
}

func New() Clock { return clockwork.NewRealClock() }

// Wait waits for d on c or context cancellation. Cancellation takes precedence
// if ctx is already done when the timer completion is observed, including when
// both signals are ready. It returns ctx.Err() in that case, otherwise nil.
func Wait(ctx context.Context, c Clock, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := c.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.Chan():
		return ctx.Err()
	}
}

type deadlineContext struct {
	context.Context
	deadline time.Time
	done     chan struct{}
	mu       sync.Mutex
	err      error
}

func (c *deadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *deadlineContext) Done() <-chan struct{}       { return c.done }
func (c *deadlineContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func WithTimeout(parent context.Context, c Clock, d time.Duration) (context.Context, context.CancelFunc) {
	return WithDeadline(parent, c, c.Now().Add(d))
}

// WithDeadline preserves both parent Err and Cause. Clockwork's fake-context
// helper intentionally ignores parent deadline cancellation, which differs
// from the application's production cancellation contract.
func WithDeadline(parent context.Context, c Clock, deadline time.Time) (context.Context, context.CancelFunc) {
	if earlier, ok := parent.Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	base, cancelCause := context.WithCancelCause(context.WithoutCancel(parent))
	ctx := &deadlineContext{Context: base, deadline: deadline, done: make(chan struct{})}
	finish := func(err, cause error) {
		ctx.mu.Lock()
		defer ctx.mu.Unlock()
		if ctx.err == nil {
			ctx.err = err
			cancelCause(cause)
			// A separate Done keeps standard derived contexts from bypassing
			// our Err and inheriting the base cancel context's Canceled value.
			close(ctx.done)
		}
	}
	cancel := func() { finish(context.Canceled, context.Canceled) }
	if err := parent.Err(); err != nil {
		finish(err, context.Cause(parent))
		return ctx, cancel
	}
	duration := deadline.Sub(c.Now())
	if duration <= 0 {
		finish(context.DeadlineExceeded, context.DeadlineExceeded)
		return ctx, cancel
	}
	timer := c.NewTimer(duration)
	go func() {
		defer timer.Stop()
		select {
		case <-parent.Done():
			finish(parent.Err(), context.Cause(parent))
		case <-timer.Chan():
			finish(context.DeadlineExceeded, context.DeadlineExceeded)
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

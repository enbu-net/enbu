package rpc

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/desktop"
	"github.com/enbu-net/enbu/pkg/clock"
)

func TestServeCancellationInterruptsOpenInput(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r, w := io.Pipe()
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	done := make(chan error, 1)
	go func() { done <- NewServer(desktop.NewService(app.New(clock.New()))).Serve(ctx, r, io.Discard) }()
	// A completed write proves Serve has started reading this still-open stream.
	if _, err := io.WriteString(w, "\n"); err != nil {
		t.Fatal(err)
	}
	cancel()
	watchdog, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve error = %v", err)
		}
	case <-watchdog.Done():
		_ = w.Close()
		if err := <-done; err != nil {
			t.Logf("Serve stopped only after closing input: %v", err)
		}
		t.Fatal("cancellation did not interrupt the open input stream")
	}
}

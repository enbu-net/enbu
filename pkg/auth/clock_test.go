package auth

import (
	"context"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/jonboulle/clockwork"
)

func TestDeviceDeadlineUsesClock(t *testing.T) {
	serverURL, transport := newDeviceFlowServer(t, deviceTokenResponse{Error: "authorization_pending"})
	c := clockwork.NewFakeClock()
	client := &deviceFlowClient{
		clock: c, deviceCodeURL: serverURL + "/device/code", tokenURL: serverURL + "/access_token", http: transport,
		wait: func(ctx context.Context, d time.Duration) error { return clock.Wait(ctx, c, d) },
	}
	done := make(chan error, 1)
	go func() {
		_, err := client.login(t.Context(), "client-id", func(DeviceAuthorization) error { return nil })
		done <- err
	}()
	if err := c.BlockUntilContext(t.Context(), 2); err != nil {
		t.Fatal(err)
	}
	c.Advance(time.Hour)
	if err := <-done; !apperr.Is(err, apperr.CodeAuthExpired) {
		t.Fatalf("fake deadline did not expire device authorization: %v", err)
	}
}

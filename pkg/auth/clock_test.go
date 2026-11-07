package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/clock"
	"github.com/jonboulle/clockwork"
)

func TestExchangeRetryUsesClock(t *testing.T) {
	var requests atomic.Int32
	server, transport := newHTTPTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(exchangeResponse{AccessToken: "token", TokenType: "bearer", Scope: "repo read:org write:packages"})
	}))
	c := clockwork.NewFakeClock()
	client := newOAuthClient(server.URL, transport, c)
	done := make(chan error, 1)
	go func() { _, err := client.exchange(t.Context(), exchangeRequest{}); done <- err }()
	if err := c.BlockUntilContext(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("retry ignored the server's delay")
	}
	c.Advance(time.Second)
	if err := <-done; err != nil || requests.Load() != 2 {
		t.Fatalf("retry did not resume: requests=%d err=%v", requests.Load(), err)
	}
}

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

package desktop

import (
	"context"
	"testing"
	"time"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/auth"
	"github.com/jonboulle/clockwork"
)

func TestOAuthExpiryUsesAppClock(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	c := clockwork.NewFakeClock()
	s := NewService(app.New(c))
	s.ctx = t.Context()
	s.openURL = func(string) error { return nil }
	canceled := make(chan struct{})
	s.authLogin = func(ctx context.Context, prompt auth.DevicePrompter) (*auth.StoredToken, error) {
		if err := prompt(auth.DeviceAuthorization{UserCode: "ABCD-1234", VerificationURI: "https://github.com/login/device"}); err != nil {
			return nil, err
		}
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}
	start, err := s.StartOAuthLogin()
	if err != nil {
		t.Fatal(err)
	}
	c.Advance(10*time.Minute - time.Nanosecond)
	status := s.GetOAuthLoginStatus(start.SessionID)
	if status.State != "pending" {
		t.Fatalf("expired early: %+v", status)
	}
	c.Advance(time.Nanosecond)
	status = s.GetOAuthLoginStatus(start.SessionID)
	if status.State != "expired" {
		t.Fatalf("missed exact deadline: %+v", status)
	}
	<-canceled
	// A result racing with expiration must not revive the expired session.
	s.setOAuthStatus(start.SessionID, OAuthStatus{State: "success", Username: "late"})
	status = s.GetOAuthLoginStatus(start.SessionID)
	if status.State != "expired" {
		t.Fatalf("late result revived session: %+v", status)
	}
}

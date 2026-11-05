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
	s.Start(t.Context())
	s.SetBrowserOpener(func(string) error { return nil })
	canceled := make(chan struct{})
	s.authLogin = func(ctx context.Context, open auth.BrowserOpener) (*auth.StoredToken, error) {
		if err := open("https://github.com/login/oauth/authorize"); err != nil {
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
	status, err := s.GetOAuthLoginStatus(start.SessionID)
	if err != nil || status.State != "pending" {
		t.Fatalf("expired early: %+v %v", status, err)
	}
	c.Advance(time.Nanosecond)
	status, err = s.GetOAuthLoginStatus(start.SessionID)
	if err != nil || status.State != "expired" {
		t.Fatalf("missed exact deadline: %+v %v", status, err)
	}
	<-canceled
	// A result racing with expiration must not revive the expired session.
	s.setOAuthStatus(start.SessionID, OAuthStatus{State: "success", Username: "late"})
	status, err = s.GetOAuthLoginStatus(start.SessionID)
	if err != nil || status.State != "expired" {
		t.Fatalf("late result revived session: %+v %v", status, err)
	}
}

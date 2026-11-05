package app

import (
	"github.com/enbu-net/enbu/app/apptest"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/jonboulle/clockwork"
	"testing"
	"time"
)

func TestJoinRequestHelperUsesInjectedClock(t *testing.T) {
	alice := newAlice(t)
	bob := newDevice(t, alice)
	c := clockwork.NewFakeClockAt(time.Unix(1234567890, 0))
	if _, err := apptest.JoinRequest(bg, bob.Storage, mustWorkspace(t, bob), bob.Identities, c); err != nil {
		t.Fatal(err)
	}
	requests, err := wsp.ListJoinRequests(bg, bob.Storage, mustWorkspace(t, bob))
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || requests[0].CreatedAt != c.Now().Unix() {
		t.Fatalf("wrong request timestamp: %+v", requests)
	}
}

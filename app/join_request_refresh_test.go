package app

import (
	"testing"
	"time"
)

// A device that asks again (after an earlier init, or after being removed)
// replaces its old request, so the admin sees the latest ask.
func TestReinitRefreshesAStaleJoinRequest(t *testing.T) {
	alice := newAlice(t)
	d := newDevice(t, alice)
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	defer func(old func() time.Time) { now = old }(now)
	now = func() time.Time { return first }
	if res, err := d.InitializeRepository(bg); err != nil || !res.Pending {
		t.Fatalf("first init: %+v %v", res, err)
	}
	now = func() time.Time { return first.Add(time.Hour) }
	if res, err := d.InitializeRepository(bg); err != nil || !res.Pending {
		t.Fatalf("second init: %+v %v", res, err)
	}
	reqs, err := alice.ListJoinRequests(bg)
	if err != nil || len(reqs) != 1 {
		t.Fatalf("requests: %v %v", reqs, err)
	}
	if !reqs[0].RequestedAt.Equal(first.Add(time.Hour)) {
		t.Fatalf("request still shows the first ask: %v", reqs[0].RequestedAt)
	}
}

package app

import (
	"context"
	"sort"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// maxJoinRequests caps the number of distinct pending requests displayed.
// The protocol loader separately bounds listed refs and fetched bytes.
var maxJoinRequests = 256

type JoinRequestInfo struct {
	DeviceID    string    `json:"device_id"`
	Fingerprint string    `json:"fingerprint"`
	Recipient   string    `json:"recipient"`
	Algorithm   string    `json:"algorithm"`
	RequestedAt time.Time `json:"requested_at"`
}

// ListJoinRequests returns verified requests from devices that are not yet
// principals, newest first. Invalid requests are skipped: they are only hints.
// Storage listing order says nothing about which request is newest, so a device
// that asked twice with different keys material appears once per distinct
// recipient and the admin chooses.
func (a *App) ListJoinRequests(ctx context.Context) (requests []JoinRequestInfo, err error) {
	defer apperr.NormalizeInto(&err)
	s, err := a.openControl(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := s.pendingRequests(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pending {
		if len(requests) >= maxJoinRequests {
			break
		}
		requests = append(requests, JoinRequestInfo{DeviceID: string(p.DeviceID()), Fingerprint: p.DeviceID().Fingerprint(), Recipient: p.Recipient,
			Algorithm: string(p.Signing.Alg), RequestedAt: time.Unix(p.CreatedAt, 0).UTC()})
	}
	sort.Slice(requests, func(i, j int) bool {
		if !requests[i].RequestedAt.Equal(requests[j].RequestedAt) {
			return requests[i].RequestedAt.After(requests[j].RequestedAt)
		}
		if requests[i].DeviceID != requests[j].DeviceID {
			return requests[i].DeviceID < requests[j].DeviceID
		}
		return requests[i].Recipient < requests[j].Recipient
	})
	return requests, nil
}

// pendingRequests lists the verified requests of devices that are not members,
// with identical requests of one device merged. The protocol loader
// bounds work. Keep the complete verified set here: approval must detect a
// conflicting recipient even when that request lies beyond the UI display cap.
func (s *session) pendingRequests(ctx context.Context) ([]wsp.PendingRequest, error) {
	all, err := wsp.ListJoinRequests(ctx, s.store, s.workspace)
	if err != nil {
		return nil, wspError(err)
	}
	type key struct {
		device    signing.DeviceID
		recipient string
	}
	seen := map[key]bool{}
	var out []wsp.PendingRequest
	for _, p := range all {
		if _, member := s.head.Principal(p.DeviceID()); member {
			continue
		}
		k := key{p.DeviceID(), p.Recipient}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out, nil
}

var errNoRequest = apperr.New(apperr.CodeInvalidArgument, "no join request from that device", nil)

// requestFor returns the one pending request of device, or an error when the
// device filed requests with different recipients and a person has to look.
func (s *session) requestFor(ctx context.Context, device signing.DeviceID) (*wsp.PendingRequest, error) {
	pending, err := s.pendingRequests(ctx)
	if err != nil {
		return nil, err
	}
	var found []wsp.PendingRequest
	for _, p := range pending {
		if p.DeviceID() == device {
			found = append(found, p)
		}
	}
	switch len(found) {
	case 0:
		return nil, errNoRequest
	case 1:
		return &found[0], nil
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument, "that device filed requests with different recipients; ask it to run 'enbu init' again after removing the stale ones", nil)
	}
}

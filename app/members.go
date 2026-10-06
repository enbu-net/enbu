package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/storage"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// maxJoinRequests bounds how many request refs are read, so someone able to
// write to storage cannot make listing unbounded.
const maxJoinRequests = 256

type MemberInfo struct {
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	Recipient   string `json:"recipient"`
	Algorithm   string `json:"algorithm"`
	Admin       bool   `json:"admin"`
	Self        bool   `json:"self"`
}

type JoinRequestInfo struct {
	DeviceID    string    `json:"device_id"`
	Fingerprint string    `json:"fingerprint"`
	Recipient   string    `json:"recipient"`
	Algorithm   string    `json:"algorithm"`
	RequestedAt time.Time `json:"requested_at"`
}

func (a *App) selfDevice(workspace string) signing.DeviceID {
	if a.Identities == nil {
		return ""
	}
	info, err := a.Identities.SignerInfo(workspace)
	if err != nil {
		return ""
	}
	return info.DeviceID
}

// ListMembers returns the principals of the verified Control.
func (a *App) ListMembers(ctx context.Context) (members []MemberInfo, err error) {
	defer apperr.NormalizeInto(&err)
	s, err := a.openControl(ctx)
	if err != nil {
		return nil, err
	}
	self := a.selfDevice(s.workspace)
	for _, p := range s.head.Principals {
		members = append(members, MemberInfo{DeviceID: string(p.ID), Fingerprint: p.ID.Fingerprint(), Recipient: p.Recipient,
			Algorithm: string(p.Signing.Alg), Admin: p.Admin, Self: p.ID == self})
	}
	return members, nil
}

// ListJoinRequests returns verified requests from devices that are not yet
// principals, newest first. Invalid requests are skipped: they are only hints.
func (a *App) ListJoinRequests(ctx context.Context) (requests []JoinRequestInfo, err error) {
	defer apperr.NormalizeInto(&err)
	s, err := a.openControl(ctx)
	if err != nil {
		return nil, err
	}
	refs, err := s.store.Refs.List(ctx, wsp.JoinRequestPrefix)
	if err != nil {
		return nil, storageError(err)
	}
	if len(refs) > maxJoinRequests {
		refs = refs[:maxJoinRequests]
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, ref := range refs {
		device := signing.DeviceID(ref[len(wsp.JoinRequestPrefix):])
		if device.Validate() != nil {
			continue
		}
		if _, member := s.head.Principal(device); member {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			req, err := s.readJoinRequest(ctx, device)
			if err != nil {
				return
			}
			mu.Lock()
			requests = append(requests, JoinRequestInfo{DeviceID: string(device), Fingerprint: device.Fingerprint(), Recipient: req.Recipient,
				Algorithm: string(req.Signing.Alg), RequestedAt: time.Unix(req.CreatedAt, 0).UTC()})
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(requests, func(i, j int) bool {
		if !requests[i].RequestedAt.Equal(requests[j].RequestedAt) {
			return requests[i].RequestedAt.After(requests[j].RequestedAt)
		}
		return requests[i].DeviceID < requests[j].DeviceID
	})
	return requests, nil
}

func (s *session) readJoinRequest(ctx context.Context, device signing.DeviceID) (*wsp.JoinRequest, error) {
	blob, _, err := getRef(ctx, s.store, wsp.JoinRequestRef(device))
	if err != nil {
		return nil, err
	}
	return wsp.VerifyJoinRequest(s.workspace, device, blob)
}

// ApproveMember adds a pending device to the workspace Control as a member,
// then re-encrypts every environment so the new member can decrypt. The caller
// is expected to have shown the device's fingerprint to the admin.
func (a *App) ApproveMember(ctx context.Context, deviceID string) (err error) {
	defer apperr.NormalizeInto(&err)
	device := signing.DeviceID(deviceID)
	if err := device.Validate(); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "invalid device id", nil)
	}
	return a.changeMembers(ctx, func(s *session, c *wsp.Control) error {
		if _, ok := c.Principal(device); ok {
			return apperr.New(apperr.CodeInvalidArgument, "device is already a member", nil)
		}
		req, err := s.readJoinRequest(ctx, device)
		if errors.Is(err, storage.ErrNotFound) {
			return apperr.New(apperr.CodeInvalidArgument, "no join request from that device", nil)
		}
		if err != nil {
			return wspError(err)
		}
		c.Principals = append(c.Principals, wsp.Principal{ID: device, Signing: req.Signing, Recipient: req.Recipient})
		return nil
	})
}

// RemoveMember removes a principal and re-encrypts every environment without
// its recipient. Plaintext the member already obtained cannot be revoked.
func (a *App) RemoveMember(ctx context.Context, deviceID string) (err error) {
	defer apperr.NormalizeInto(&err)
	device := signing.DeviceID(deviceID)
	return a.changeMembers(ctx, func(s *session, c *wsp.Control) error {
		kept := c.Principals[:0:0]
		for _, p := range c.Principals {
			if p.ID != device {
				kept = append(kept, p)
			}
		}
		if len(kept) == len(c.Principals) {
			return apperr.New(apperr.CodeInvalidArgument, "device is not a member", nil)
		}
		c.Principals = kept
		return requireAdmin(c)
	})
}

// requireAdmin keeps the workspace manageable: a Control with no admin could
// never be changed again.
func requireAdmin(c *wsp.Control) error {
	for _, p := range c.Principals {
		if p.Admin {
			return nil
		}
	}
	return apperr.New(apperr.CodeInvalidArgument, "the workspace needs at least one admin", nil)
}

// SetAdmin grants or revokes the membership-admin flag. It does not change
// which secrets a member can read.
func (a *App) SetAdmin(ctx context.Context, deviceID string, admin bool) (err error) {
	defer apperr.NormalizeInto(&err)
	device := signing.DeviceID(deviceID)
	return a.changeMembers(ctx, func(s *session, c *wsp.Control) error {
		for i := range c.Principals {
			if c.Principals[i].ID == device {
				c.Principals[i].Admin = admin
				return requireAdmin(c)
			}
		}
		return apperr.New(apperr.CodeInvalidArgument, "device is not a member", nil)
	})
}

func (a *App) changeMembers(ctx context.Context, mutate func(*session, *wsp.Control) error) error {
	const attempts = 3
	var s *session
	for attempt := 0; ; attempt++ {
		var err error
		if s, err = a.openSession(ctx); err != nil {
			return err
		}
		if p, _ := s.head.Principal(s.self()); !p.Admin {
			s.Close()
			return apperr.New(apperr.CodeAccessDenied, "only a workspace admin can change members", nil)
		}
		v, err := wsp.UpdateControl(ctx, s.store, s.head, s.signer, func(c *wsp.Control) error { return mutate(s, c) })
		if err == nil {
			err = s.cps.AcceptControl(v)
		}
		s.Close()
		if err == nil {
			break
		}
		if errors.Is(err, storage.ErrConflict) && attempt+1 < attempts {
			continue // another admin changed the Control; retry on the new head
		}
		if errors.Is(err, wsp.ErrInvalid) {
			return wspError(err)
		}
		return storageError(err)
	}
	return a.reencryptAll(ctx)
}

// reencryptAll re-signs and re-encrypts every environment for the recipient set
// of the current Control.
func (a *App) reencryptAll(ctx context.Context) error {
	cfg, err := a.loadProject()
	if err != nil {
		return err
	}
	for _, env := range cfg.EnvironmentNames() {
		if err := a.SyncSecrets(ctx, env); err != nil {
			return fmt.Errorf("re-encrypting %s: %w", env, err)
		}
	}
	return nil
}

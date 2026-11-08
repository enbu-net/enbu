package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/wsp"
)

type MemberInfo struct {
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	Recipient   string `json:"recipient"`
	Algorithm   string `json:"algorithm"`
	Admin       bool   `json:"admin"`
	Self        bool   `json:"self"`
}

func (a *App) selfDevice(workspace string) signing.DeviceID {
	if a.Identities == nil {
		return ""
	}
	info, err := a.Identities.Info(workspace)
	if err != nil {
		return ""
	}
	return signing.DeviceID(info.DeviceID)
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

// ApproveMember adds a pending device to the workspace Control as a member,
// then re-encrypts every environment for the new recipient set. The caller is expected to have
// shown the device's fingerprint to the admin.
func (a *App) ApproveMember(ctx context.Context, deviceID string) (err error) {
	defer apperr.NormalizeInto(&err)
	device := signing.DeviceID(deviceID)
	if err := device.Validate(); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "invalid device id", nil)
	}
	return a.changeMembers(ctx, true, nil, func(s *session, c *wsp.Control) error {
		if _, member := c.Principal(device); member {
			return apperr.New(apperr.CodeInvalidArgument, "device is already a member", nil)
		}
		req, err := s.requestFor(ctx, device)
		if err != nil {
			return err
		}
		c.Principals = append(c.Principals, wsp.Principal{ID: device, Signing: req.Signing, Recipient: req.Recipient})
		return nil
	})
}

// RemoveMember removes a principal. Every environment is first re-encrypted
// without its recipient, under the Control that still lists it, and only then
// is the Control without it published. Its revisions are so already merged
// into a remaining member's when it stops being trusted, and nothing a
// remaining member read is set aside. Plaintext the member already obtained
// cannot be revoked.
func (a *App) RemoveMember(ctx context.Context, deviceID string) (err error) {
	defer apperr.NormalizeInto(&err)
	device := signing.DeviceID(deviceID)
	remove := func(c *wsp.Control) error {
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
	}
	s, err := a.openAdminSession(ctx)
	if err != nil {
		return err
	}
	before := s.view
	trial := s.head.Control
	trial.Principals = append([]wsp.Principal(nil), trial.Principals...)
	s.Close()
	if err := remove(&trial); err != nil {
		return err
	}
	if err := a.reencryptAll(ctx, device); err != nil {
		return err
	}
	return a.changeMembers(ctx, false, before, func(_ *session, c *wsp.Control) error { return remove(c) })
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
	return a.changeMembers(ctx, false, nil, func(s *session, c *wsp.Control) error {
		for i := range c.Principals {
			if c.Principals[i].ID == device {
				c.Principals[i].Admin = admin
				return requireAdmin(c)
			}
		}
		return apperr.New(apperr.CodeInvalidArgument, "device is not a member", nil)
	})
}

// changeMembers appends an admin-signed Control. When reencrypt is set it then
// re-encrypts every environment for the new recipient set. Changing who is an
// admin does not change the recipients, so it passes false.
//
// on is the Control view to append to, or nil for the current one. A removal
// appends to the view it re-encrypted under: a change another admin made
// meanwhile then forks the Control, and joining the fork re-encrypts again.
func (a *App) changeMembers(ctx context.Context, reencrypt bool, on *wsp.ControlView, mutate func(*session, *wsp.Control) error) error {
	s, err := a.openAdminSession(ctx)
	if err != nil {
		return err
	}
	if on == nil {
		on = s.view
	}
	v, err := wsp.UpdateControl(ctx, s.store, on, s.signer, func(c *wsp.Control) error { return mutate(s, c) })
	s.Close()
	if err != nil {
		var appErr *apperr.Error
		if errors.As(err, &appErr) {
			return err // validation from mutate keeps its own code
		}
		return wspError(err)
	}
	// The new Control is published. Record it so storage cannot later hide it.
	if err := a.acceptControlHead(ctx, v); err != nil {
		return err
	}
	if !reencrypt {
		return nil
	}
	// The Control is already committed here, so a failure leaves membership
	// changed but some environments still encrypted for the old recipient set.
	// Say so explicitly: retrying approve/remove would fail on the new state.
	if err := a.reencryptAll(ctx, ""); err != nil {
		return apperr.Wrap(apperr.CodeReencryptIncomplete, "membership changed but re-encryption is incomplete; run 'enbu sync' for each environment", err, nil)
	}
	return nil
}

// openAdminSession opens a session of a workspace admin.
func (a *App) openAdminSession(ctx context.Context) (*session, error) {
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, err
	}
	if p, _ := s.head.Principal(s.self()); !p.Admin {
		s.Close()
		return nil, apperr.New(apperr.CodeAccessDenied, "only a workspace admin can change members", nil)
	}
	return s, nil
}

// acceptControlHead reloads the Control DAG, which records the newest heads in
// the checkpoint, and checks that v is part of it.
func (a *App) acceptControlHead(ctx context.Context, v *wsp.Verified) error {
	s, err := a.openControlView(ctx)
	if err != nil {
		return err
	}
	if _, ok := s.view.Get(v.Digest); !ok {
		return wspError(fmt.Errorf("%w: the control just published is missing from storage", wsp.ErrRollback))
	}
	return nil
}

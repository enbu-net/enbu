package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/signing"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// maxJoinRequests bounds how many request refs are read, so someone able to
// write to storage cannot make listing unbounded.
var maxJoinRequests = 256

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
// with identical requests of one device merged. At most maxJoinRequests are
// read, so someone able to write to storage cannot make the list unbounded.
func (s *session) pendingRequests(ctx context.Context) ([]wsp.PendingRequest, error) {
	all, err := wsp.ListJoinRequests(ctx, s.store, s.workspace)
	if err != nil {
		return nil, storageError(err)
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
		if len(out) >= maxJoinRequests {
			break
		}
	}
	return out, nil
}

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
		return nil, apperr.New(apperr.CodeInvalidArgument, "no join request from that device", nil)
	case 1:
		return &found[0], nil
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument, "that device filed requests with different recipients; ask it to run 'enbu init' again after removing the stale ones", nil)
	}
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
	return a.changeMembers(ctx, true, func(s *session, c *wsp.Control) error {
		if _, ok := c.Principal(device); ok {
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

// RemoveMember removes a principal and re-encrypts every environment without
// its recipient. Plaintext the member already obtained cannot be revoked.
func (a *App) RemoveMember(ctx context.Context, deviceID string) (err error) {
	defer apperr.NormalizeInto(&err)
	device := signing.DeviceID(deviceID)
	// Accept the current states first, while the member is still one. After the
	// removal an admin can only take over a state it has already accepted.
	a.acceptCurrentStates(ctx)
	return a.changeMembers(ctx, true, func(s *session, c *wsp.Control) error {
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
	return a.changeMembers(ctx, false, func(s *session, c *wsp.Control) error {
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
func (a *App) changeMembers(ctx context.Context, reencrypt bool, mutate func(*session, *wsp.Control) error) error {
	s, err := a.openSession(ctx)
	if err != nil {
		return err
	}
	if p, _ := s.head.Principal(s.self()); !p.Admin {
		s.Close()
		return apperr.New(apperr.CodeAccessDenied, "only a workspace admin can change members", nil)
	}
	v, err := wsp.UpdateControl(ctx, s.store, s.view, s.signer, func(c *wsp.Control) error { return mutate(s, c) })
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
	if err := a.reencryptAll(ctx); err != nil {
		return apperr.Wrap(apperr.CodeReencryptIncomplete, "membership changed but re-encryption is incomplete; run 'enbu sync' for each environment", err, nil)
	}
	return nil
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

// ResolveControlFork joins competing Control heads. Two admins changed the
// members at the same time; the resolution keeps only principals every head
// lists and admin rights every head grants, so nothing is granted by chance.
// Anyone it dropped, or anything it did not grant, is added again afterwards
// by a normal approval.
func (a *App) ResolveControlFork(ctx context.Context) (err error) {
	defer apperr.NormalizeInto(&err)
	s, err := a.openControlView(ctx)
	if err != nil {
		return err
	}
	if s.head != nil {
		return apperr.New(apperr.CodeInvalidArgument, "the workspace members are not forked", nil)
	}
	if a.Identities == nil {
		return fmt.Errorf("identity store is not initialized")
	}
	if s.signer, err = a.Identities.LoadSigner(s.workspace); err != nil {
		return fmt.Errorf("loading signing key: %w", err)
	}
	defer s.Close()
	_, err = wsp.ResolveFork(ctx, s.store, s.view, s.signer, func(c *wsp.Control) error {
		kept := c.Principals[:0:0]
		for _, p := range c.Principals {
			inAll, adminInAll := true, true
			for _, h := range s.view.Heads {
				q, ok := h.Principal(p.ID)
				inAll = inAll && ok
				adminInAll = adminInAll && ok && q.Admin
			}
			if inAll {
				p.Admin = adminInAll
				kept = append(kept, p)
			}
		}
		c.Principals = kept
		return requireAdmin(c)
	})
	if err != nil {
		var appErr *apperr.Error
		if errors.As(err, &appErr) {
			return err
		}
		return wspError(err)
	}
	return nil
}

// reencryptAll re-signs and re-encrypts every environment for the recipient set
// of the current Control.
func (a *App) reencryptAll(ctx context.Context) error {
	cfg, err := a.loadProject()
	if err != nil {
		return err
	}
	// Keep going after a failure: every environment left behind stays encrypted
	// for the old recipient set, and the error should name all of them.
	var errs []error
	for _, env := range cfg.EnvironmentNames() {
		if err := a.SyncSecrets(ctx, env); err != nil {
			errs = append(errs, fmt.Errorf("re-encrypting %s: %w", env, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// acceptCurrentStates reads every environment's current state, which records it
// in this device's checkpoint. It is best effort: an environment that cannot be
// read now will fail to re-encrypt later with its own error.
func (a *App) acceptCurrentStates(ctx context.Context) {
	cfg, err := a.loadProject()
	if err != nil {
		return
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return
	}
	defer s.Close()
	for _, env := range cfg.EnvironmentNames() {
		_, _ = s.readResource(ctx, env, nil, true)
	}
}

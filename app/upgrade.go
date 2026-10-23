package app

import (
	"context"
	"errors"
	"io/fs"
	"time"

	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/wsp"
)

// keyUpdater is an identity store that can replace this device's encryption
// key while keeping its signing key, and so its device id.
type keyUpdater interface {
	CreatePending(workspaceID string) (identity.Identity, identity.PublicInfo, string, error)
	PendingInfo(workspaceID string) (identity.PublicInfo, error)
	PromotePending(workspaceID string) error
}

// retainedLoader is an identity store that keeps identities besides the
// current one that can still decrypt: a key update's pending identity, and the
// identity it replaced.
type retainedLoader interface {
	LoadRetained(workspaceID string) ([]identity.Identity, error)
}

type KeyUpdateResult struct {
	Backend     string `json:"backend"`
	Algorithm   string `json:"algorithm"`
	Recipient   string `json:"recipient"`
	DeviceID    string `json:"device_id"`
	Fingerprint string `json:"fingerprint"`
	// Pending is set while an admin still has to approve the new key. Until
	// then this device decrypts with either key.
	Pending  bool     `json:"pending"`
	Warnings []string `json:"-"`
}

// UpgradeIdentity gives this device a post-quantum (hybrid ML-KEM-768)
// encryption key. The device asks to swap its recipient with a request signed
// by its own signing key; an admin approves it like a join request, which
// re-encrypts every environment. An admin's own update is applied directly.
func (a *App) UpgradeIdentity(ctx context.Context) (result *KeyUpdateResult, err error) {
	defer apperr.NormalizeInto(&err)
	ku, ok := a.Identities.(keyUpdater)
	if !ok {
		return nil, errors.New("this identity store cannot update keys")
	}
	s, err := a.openSession(ctx)
	if err != nil {
		return nil, err
	}
	self, _ := s.head.Principal(s.self())
	if age.IsPostQuantum(self.Recipient) {
		s.Close()
		return nil, apperr.New(apperr.CodeInvalidArgument, "this device already uses a post-quantum key", nil)
	}
	id, info, warning, err := ku.CreatePending(s.workspace)
	if err != nil {
		s.Close()
		return nil, identityError(err)
	}
	_ = id.Close()
	result = &KeyUpdateResult{Backend: info.Backend, Algorithm: info.Algorithm, Recipient: info.Recipient,
		DeviceID: string(self.ID), Fingerprint: self.ID.Fingerprint(), Pending: true}
	if warning != "" {
		result.Warnings = append(result.Warnings, warning)
		a.emit(warning)
	}
	blob, err := wsp.NewKeyUpdateRequest(s.workspace, info.Recipient, self.Recipient, time.Now(), s.signer)
	if err != nil {
		s.Close()
		return nil, err
	}
	_, err = wsp.PublishJoinRequest(ctx, s.store, blob)
	s.Close()
	if err != nil {
		return nil, storageError(err)
	}
	if !self.Admin {
		return result, nil
	}
	if err := a.ApproveMember(ctx, string(self.ID)); err != nil {
		return nil, err
	}
	// Re-encrypting after the approval opens sessions that may have promoted
	// the key already.
	if err := ku.PromotePending(s.workspace); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, identityError(err)
	}
	result.Pending = false
	return result, nil
}

// promoteApprovedKey makes a pending key current once the verified Control
// lists it as this device's recipient. Failing to do so is not fatal: the
// pending identity is still loaded for decryption, and the next session retries.
func (a *App) promoteApprovedKey(s *session) {
	ku, ok := a.Identities.(keyUpdater)
	if !ok {
		return
	}
	pending, err := ku.PendingInfo(s.workspace)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	self, member := s.head.Principal(s.self())
	if err != nil || !member || self.Recipient != pending.Recipient {
		return
	}
	if err := ku.PromotePending(s.workspace); err != nil {
		a.emit("Could not switch to the approved post-quantum key yet: " + err.Error())
	}
}

package simulation

import (
	"context"
	"errors"
	"fmt"

	agecrypto "filippo.io/age"
	"github.com/enbu-net/enbu/pkg/age"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/config"
	"github.com/enbu-net/enbu/pkg/wsp"
	"github.com/opencontainers/go-digest"
)

// DeviceReplacement restores a checkout without the lost laptop's private keys.
// The old laptop remains an attacker holding those keys and registry access.
func (w *World) DeviceReplacement(ctx context.Context) error {
	ctx = wsp.WithSerialHeadReads(ctx)
	target := len(w.Devices) - 1
	a := w.Devices[0].App
	if err := a.CreateEnvironment("production"); err != nil {
		return err
	}
	if err := a.AddSecret(ctx, "production", "TOKEN", "before-loss"); err != nil {
		return err
	}
	w.Model["production"] = map[string]string{"TOKEN": "before-loss"}
	if err := a.SwitchEnvironment("default"); err != nil {
		return err
	}
	if err := w.Share(0); err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	cfg, err := config.LoadProjectFrom(a.RepositoryDir)
	if err != nil {
		return err
	}
	view, err := wsp.LoadControl(ctx, w.Devices[0].Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return err
	}
	oldControl, err := view.Head()
	if err != nil {
		return err
	}
	oldStates, err := wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource("production"))
	if err != nil {
		return err
	}
	if len(oldStates.Heads) != 1 {
		return fmt.Errorf("replacement fixture lacks old ciphertext")
	}
	oldCipher, err := wsp.ReadCiphertext(ctx, w.Devices[0].Store, oldStates.Heads[0])
	if err != nil {
		return err
	}
	retiredKeys := w.Devices[target].Keys
	retiredID := w.Devices[target].ID
	if err := a.RemoveMember(ctx, retiredID); err != nil {
		return err
	}
	// A backup of the checkout/checkpoints is not a backup of either private key.
	w.Devices[target].Keys = &Keys{Tape: w.Tape, Device: target}
	w.Restart(target)
	replacement, err := w.Devices[target].App.InitializeRepository(ctx)
	if err != nil {
		return err
	}
	if !replacement.Pending || !replacement.KeyCreated || replacement.DeviceID == retiredID {
		return fmt.Errorf("replacement inherited old identity or authority: %+v", replacement)
	}
	w.Devices[target].ID = replacement.DeviceID
	for _, env := range []string{"default", "production"} {
		if _, err := w.Devices[target].App.ListSecrets(ctx, env); requireCode(err, apperr.CodeNotMember) != nil {
			return fmt.Errorf("unapproved replacement reads %s: %v", env, err)
		}
	}
	if err := a.ApproveMember(ctx, replacement.DeviceID); err != nil {
		return err
	}
	if err := a.EditSecret(ctx, "production", "TOKEN", "rotated-after-loss"); err != nil {
		return err
	}
	w.Model["production"]["TOKEN"] = "rotated-after-loss"
	// Approval exposes current data, not ciphertext encrypted before joining.
	newKey, err := w.Devices[target].Keys.Load(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	_, err = age.Decrypt(oldCipher, newKey.Identity)
	_ = newKey.Close()
	var noMatch *agecrypto.NoIdentityMatchError
	if !errors.As(err, &noMatch) {
		return fmt.Errorf("new laptop decrypted pre-join ciphertext: %v", err)
	}
	oldKey, err := retiredKeys.Load(cfg.WorkspaceID)
	if err != nil {
		return err
	}
	defer func() { _ = oldKey.Close() }()
	// Revocation cannot erase past knowledge. The fixture must retain that threat.
	if _, err := age.Decrypt(oldCipher, oldKey.Identity); err != nil {
		return fmt.Errorf("lost laptop did not retain its old key: %w", err)
	}
	view, err = wsp.LoadControl(ctx, w.Devices[0].Store, cfg.WorkspaceID, digest.Digest(cfg.ControlGenesis), nil)
	if err != nil {
		return err
	}
	current, err := wsp.LoadStates(ctx, w.Devices[0].Store, view, cfg.WorkspaceID, cfg.Resource("production"))
	if err != nil {
		return err
	}
	for _, head := range current.Heads {
		blob, err := wsp.ReadCiphertext(ctx, w.Devices[0].Store, head)
		if err != nil {
			return err
		}
		_, err = age.Decrypt(blob, oldKey.Identity)
		if !errors.As(err, &noMatch) {
			return fmt.Errorf("lost laptop decrypted rotated ciphertext: %v", err)
		}
	}
	// The attacker can still make genuine signatures under its former Control.
	activeKeys := w.Devices[target].Keys
	err = func() error {
		w.Devices[target].Keys = retiredKeys
		defer func() { w.Devices[target].Keys = activeKeys }()
		_, err := w.publishNodeAtControl(ctx, target, oldControl.Digest, map[string]string{"BASE": "stolen-laptop-branch"})
		return err
	}()
	if err != nil {
		return err
	}
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	members, err := a.ListMembers(ctx)
	if err != nil {
		return err
	}
	seenNew := false
	for _, member := range members {
		if member.DeviceID == retiredID {
			return fmt.Errorf("lost laptop reappeared in membership")
		}
		if member.DeviceID == replacement.DeviceID {
			seenNew = true
			if member.Admin {
				return fmt.Errorf("replacement silently became admin")
			}
		}
	}
	if !seenNew {
		return fmt.Errorf("approved replacement missing")
	}
	if err := w.Devices[target].App.AddSecret(ctx, "default", "REPLACEMENT_WRITE", "fresh-key"); err != nil {
		return err
	}
	w.Model["default"]["REPLACEMENT_WRITE"] = "fresh-key"
	if _, err := a.CompactHistory(ctx, "default", 1); err != nil {
		return err
	}
	for i := range w.Devices {
		w.Restart(i)
	}
	if err := w.Tape.Observe("device-replaced", retiredID, replacement.DeviceID); err != nil {
		return err
	}
	if err := w.Check(ctx, "production"); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}

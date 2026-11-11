package simulation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/enbu-net/enbu/app"
	"github.com/enbu-net/enbu/pkg/apperr"
	"github.com/enbu-net/enbu/pkg/identity"
	"github.com/enbu-net/enbu/pkg/signing"
)

// The real key store's hardware/UI failure is outside DST, but the App's
// response to a temporarily unavailable backend is part of the team contract.
type lockedDeviceKeys struct{ *Keys }

func (k lockedDeviceKeys) Create(string) (identity.Identity, identity.PublicInfo, string, error) {
	return nil, identity.PublicInfo{}, "", &identity.UnavailableError{Reason: "simulated locked key store"}
}
func (k lockedDeviceKeys) LoadSigner(string) (signing.Signer, error) {
	return nil, &identity.UnavailableError{Reason: "simulated locked key store"}
}

func (w *World) LockedDevice(ctx context.Context) error {
	d := w.Devices[1]
	path := filepath.Join(d.App.RepositoryDir, ".env")
	original := []byte("LOCAL_ONLY=personal\nBASE=old\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		return err
	}
	d.App.Identities = lockedDeviceKeys{d.Keys}
	for _, op := range []struct {
		name string
		run  func() error
	}{
		{"init", func() error { _, err := d.App.InitializeRepository(ctx, app.InitOptions{}); return err }},
		{"read", func() error { _, err := d.App.ListSecrets(ctx, "default"); return err }},
		{"write", func() error { return d.App.EditSecret(ctx, "default", "BASE", "must-not-commit") }},
		{"pull", func() error { return d.App.PullSecretsToFile(ctx, "default") }},
		{"sync", func() error { return d.App.SyncSecrets(ctx, "default") }},
	} {
		err := op.run()
		if check := requireCode(err, apperr.CodeIdentityUnavailable); check != nil {
			return fmt.Errorf("locked device %s: %w", op.name, check)
		}
		if err := w.Tape.Observe("locked-device-denial", op.name, ErrorCode(err)); err != nil {
			return err
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(got) != string(original) {
		return fmt.Errorf("locked pull modified local file")
	}
	if err := w.Devices[0].App.EditSecret(ctx, "default", "BASE", "teammate-while-locked"); err != nil {
		return err
	}
	w.Model["default"]["BASE"] = "teammate-while-locked"
	// Restart and unlock the backend, retaining only its durable synthetic keys.
	w.Restart(1)
	if err := w.Check(ctx, "default"); err != nil {
		return err
	}
	if err := w.Devices[1].App.AddSecret(ctx, "default", "AFTER_UNLOCK", "kept"); err != nil {
		return err
	}
	w.Model["default"]["AFTER_UNLOCK"] = "kept"
	if err := w.Devices[1].App.PullSecretsToFile(ctx, "default"); err != nil {
		return err
	}
	expected := clone(w.Model["default"])
	expected["LOCAL_ONLY"] = "personal"
	if err := w.checkOutput("unlocked-file", path, expected); err != nil {
		return err
	}
	return w.Check(ctx, "default")
}
